use crate::curve::Curve;
use crate::hd::ed25519_scalar_mult_base_noclamp;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;
use sha2::Digest;

/// Algorand chain signer using BIP32-Ed25519 with Peikert's amendment.
///
/// Algorand addresses are base32-encoded public keys with a 4-byte SHA-512/256 checksum.
/// Transaction signing uses the RFC 8032 EdDSA scheme with the "TX" domain separator.
pub struct AvmSigner;

impl AvmSigner {
    /// Derive the Ed25519 public key from the BIP32-Ed25519 scalar (kL).
    ///
    /// The private key here is the 32-byte scalar from BIP32-Ed25519 derivation.
    /// Unlike standard Ed25519, the scalar is pre-clamped during root key generation,
    /// so we use noclamp base-point multiplication.
    fn public_key_from_scalar(scalar: &[u8]) -> Result<[u8; 32], SignerError> {
        let scalar_bytes: [u8; 32] = scalar.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", scalar.len()))
        })?;
        Ok(ed25519_scalar_mult_base_noclamp(&scalar_bytes))
    }

    /// Encode an Algorand address from a 32-byte public key.
    ///
    /// Format: base32(pubkey || checksum) where checksum = SHA-512/256(pubkey)[28..32]
    fn encode_address(pubkey: &[u8; 32]) -> String {
        let hash = sha2::Sha512_256::digest(pubkey);
        let checksum = &hash[28..32]; // last 4 bytes

        let mut addr_bytes = [0u8; 36];
        addr_bytes[..32].copy_from_slice(pubkey);
        addr_bytes[32..].copy_from_slice(checksum);

        // Algorand uses base32 without padding, 58 characters
        data_encoding::BASE32_NOPAD.encode(&addr_bytes)
    }

    /// Sign a message using BIP32-Ed25519 scalar following RFC 8032 Section 5.1.6.
    ///
    /// This implements EdDSA signing with the BIP32-Ed25519 extended key.
    /// The scalar is used directly (no hashing of secret key as in standard Ed25519),
    /// and kR is used as the nonce source (instead of the second half of H(sk)).
    ///
    /// For the chain signer interface, we only receive the 32-byte scalar (kL),
    /// so we use standard ed25519-dalek signing which re-derives from the key.
    /// This works because Algorand nodes verify using standard Ed25519 verification.
    fn sign_with_scalar(scalar: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // For BIP32-Ed25519, we perform RFC 8032 EdDSA signing manually.
        // The scalar is pre-clamped from BIP32-Ed25519 derivation.
        //
        // However, since the ChainSigner interface only provides the 32-byte
        // scalar (not the full extended key), and Algorand nodes use standard
        // Ed25519 verification, we use ed25519-dalek which works with 32-byte seeds.
        //
        // Note: ed25519-dalek's SigningKey::from_bytes treats the input as a seed
        // and hashes it internally. For BIP32-Ed25519, the scalar IS the clamped
        // result. We need to use the hazmat API for correct signing.
        use curve25519_dalek::scalar::Scalar;
        use ed25519_dalek::hazmat::raw_sign;
        use ed25519_dalek::hazmat::ExpandedSecretKey;

        let scalar_bytes: [u8; 32] = scalar.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", scalar.len()))
        })?;

        // The expanded secret key for BIP32-Ed25519:
        // - scalar: the clamped kL from derivation, converted to curve25519-dalek Scalar
        // - hash_prefix: we use SHA-512(scalar) right half as nonce source
        //   This is a simplification since we don't have kR in the ChainSigner interface.
        let hash = sha2::Sha512::digest(scalar_bytes);
        let mut hash_prefix = [0u8; 32];
        hash_prefix.copy_from_slice(&hash[32..64]);

        let expanded = ExpandedSecretKey {
            scalar: Scalar::from_bytes_mod_order(scalar_bytes),
            hash_prefix,
        };

        let pubkey = Self::public_key_from_scalar(scalar)?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
            .map_err(|e| SignerError::SigningFailed(format!("invalid public key: {}", e)))?;

        let signature = raw_sign::<sha2::Sha512>(&expanded, message, &verifying_key);

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey.to_vec()),
        })
    }
}

impl ChainSigner for AvmSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Avm
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519Bip32
    }

    fn coin_type(&self) -> u32 {
        283
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let pubkey = Self::public_key_from_scalar(private_key)?;
        Ok(Self::encode_address(&pubkey))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        Self::sign_with_scalar(private_key, message)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Algorand doesn't have a special message signing prefix
        Self::sign_with_scalar(private_key, message)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Algorand transaction signing: sign("TX" || msgpack_encoded_tx)
        // The tx_bytes should already be the prefix-encoded transaction
        // (i.e., "TX" prefix + msgpack bytes), as produced by the SDK.
        Self::sign_with_scalar(private_key, tx_bytes)
    }

    fn encode_signed_transaction(
        &self,
        _tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Algorand signed transactions are msgpack-encoded objects containing
        // the signature and the transaction. The caller is responsible for
        // constructing the final msgpack structure.
        // We return the raw 64-byte signature for the caller to embed.
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        Ok(signature.signature.clone())
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // BIP-44 path for Algorand: m/44'/283'/account'/0/0
        // Using Peikert's BIP32-Ed25519 with mixed hardened/non-hardened
        format!("m/44'/283'/{}'/0/0", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_properties() {
        let signer = AvmSigner;
        assert_eq!(signer.chain_type(), ChainType::Avm);
        assert_eq!(signer.curve(), Curve::Ed25519Bip32);
        assert_eq!(signer.coin_type(), 283);
    }

    #[test]
    fn test_derivation_path() {
        let signer = AvmSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/283'/0'/0/0");
        assert_eq!(signer.default_derivation_path(1), "m/44'/283'/1'/0/0");
        assert_eq!(signer.default_derivation_path(5), "m/44'/283'/5'/0/0");
    }

    #[test]
    fn test_address_encoding() {
        // Known test vector from TypeScript reference implementation:
        // Public key: 7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9
        let pubkey_hex = "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9";
        let pubkey_bytes: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
        let address = AvmSigner::encode_address(&pubkey_bytes);
        // Algorand address: 58 characters, uppercase base32
        assert_eq!(address.len(), 58);
        assert!(address.chars().all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));

        // Verify roundtrip: decode address, extract pubkey, re-encode
        let decoded = data_encoding::BASE32_NOPAD.decode(address.as_bytes()).unwrap();
        assert_eq!(&decoded[..32], pubkey_bytes.as_slice());
        // Last 4 bytes should be checksum
        let hash = sha2::Sha512_256::digest(&pubkey_bytes);
        assert_eq!(&decoded[32..36], &hash[28..32]);
    }

    #[test]
    fn test_address_format() {
        // Use a simple known scalar to test address format
        let scalar = [1u8; 32];
        let signer = AvmSigner;
        let address = signer.derive_address(&scalar).unwrap();
        // Algorand addresses are 58 characters, uppercase base32
        assert_eq!(address.len(), 58);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = AvmSigner;
        // Use a valid clamped scalar
        let mut scalar = [0u8; 32];
        scalar[0] = 0x40; // Set a valid scalar value
        scalar[31] = 0x40; // Ensure second-highest bit set

        let message = b"test message for algorand";
        let result = signer.sign(&scalar, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);

        // Verify using ed25519-dalek
        let pubkey = result.public_key.as_ref().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
            &pubkey.clone().try_into().unwrap()
        ).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(
            &result.signature.try_into().unwrap()
        );
        use ed25519_dalek::Verifier;
        verifying_key.verify(message, &sig).expect("signature should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let signer = AvmSigner;
        let mut scalar = [0u8; 32];
        scalar[0] = 0x40;
        scalar[31] = 0x40;

        let message = b"hello algorand";
        let sig1 = signer.sign(&scalar, message).unwrap();
        let sig2 = signer.sign(&scalar, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_invalid_key() {
        let signer = AvmSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
    }

    #[test]
    fn test_sign_transaction() {
        let signer = AvmSigner;
        let mut scalar = [0u8; 32];
        scalar[0] = 0x40;
        scalar[31] = 0x40;

        // Simulate a prefix-encoded transaction (TX || msgpack)
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(b"TX");
        tx_bytes.extend_from_slice(b"fake_msgpack_transaction_data");

        let result = signer.sign_transaction(&scalar, &tx_bytes).unwrap();
        assert_eq!(result.signature.len(), 64);
    }

    #[test]
    fn test_encode_signed_transaction() {
        let signer = AvmSigner;
        let sig_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: Some(vec![0u8; 32]),
        };
        let result = signer.encode_signed_transaction(b"tx", &sig_output).unwrap();
        assert_eq!(result.len(), 64);
    }
}
