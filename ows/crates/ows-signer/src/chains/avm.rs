use crate::curve::Curve;
use crate::hd::ed25519_scalar_mult_base_noclamp;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ows_core::ChainType;
use sha2::Digest;

/// Algorand chain signer using BIP32-Ed25519 with Peikert's amendment.
///
/// Algorand addresses are base32-encoded public keys with a 4-byte SHA-512/256 checksum.
/// Transaction signing uses the RFC 8032 EdDSA scheme with the "TX" domain separator.
/// Message signing uses the "MX" domain separator per ARC-60.
///
/// The signer receives the full 96-byte extended key [kL(32) || kR(32) || chainCode(32)]
/// from BIP32-Ed25519 derivation. kL is the private scalar, kR is the nonce source for
/// RFC 8032 EdDSA signing — matching the Algorand Foundation's xHD-Wallet-API rawSign().
pub struct AvmSigner;

impl AvmSigner {
    /// Extract kL (the 32-byte private scalar) from the extended key.
    /// Accepts either 96-byte extended key or 32-byte scalar for backwards compatibility.
    fn extract_kl(private_key: &[u8]) -> Result<[u8; 32], SignerError> {
        if private_key.len() == 96 {
            let mut kl = [0u8; 32];
            kl.copy_from_slice(&private_key[..32]);
            Ok(kl)
        } else if private_key.len() == 32 {
            private_key
                .try_into()
                .map_err(|_| SignerError::InvalidPrivateKey("expected 32 or 96 bytes".into()))
        } else {
            Err(SignerError::InvalidPrivateKey(format!(
                "expected 32 or 96 bytes, got {}",
                private_key.len()
            )))
        }
    }

    /// Derive the Ed25519 public key from the BIP32-Ed25519 scalar (kL).
    ///
    /// The private key here is the 32-byte scalar from BIP32-Ed25519 derivation.
    /// Unlike standard Ed25519, the scalar is pre-clamped during root key generation,
    /// so we use noclamp base-point multiplication.
    fn public_key_from_scalar(scalar: &[u8; 32]) -> [u8; 32] {
        ed25519_scalar_mult_base_noclamp(scalar)
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

    /// Sign a message using the BIP32-Ed25519 extended key following RFC 8032 Section 5.1.6.
    ///
    /// This implements EdDSA signing matching the Algorand Foundation's xHD-Wallet-API
    /// rawSign() function exactly:
    ///   - kL (bytes 0..32): the private scalar
    ///   - kR (bytes 32..64): the nonce source for deterministic nonce generation
    ///   - Nonce: r = SHA-512(kR || message) mod q
    ///   - R = r * G
    ///   - S = (r + SHA-512(R || pubkey || message) * kL) mod q
    ///   - Signature = R || S (64 bytes)
    fn sign_extended(extended_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        use curve25519_dalek::scalar::Scalar;
        use ed25519_dalek::hazmat::raw_sign;
        use ed25519_dalek::hazmat::ExpandedSecretKey;

        let kl = Self::extract_kl(extended_key)?;

        // Extract kR (nonce source) — use real kR from extended key if available,
        // matching AF's rawSign() which does: raw.slice(32, 64)
        let kr = if extended_key.len() == 96 {
            let mut kr = [0u8; 32];
            kr.copy_from_slice(&extended_key[32..64]);
            kr
        } else {
            // Fallback for 32-byte keys: derive nonce deterministically from kL.
            // This produces valid but different signatures than the AF's implementation.
            let hash = sha2::Sha512::digest(kl);
            let mut kr = [0u8; 32];
            kr.copy_from_slice(&hash[32..64]);
            kr
        };

        let expanded = ExpandedSecretKey {
            scalar: Scalar::from_bytes_mod_order(kl),
            hash_prefix: kr,
        };

        let pubkey = Self::public_key_from_scalar(&kl);
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
        let kl = Self::extract_kl(private_key)?;
        let pubkey = Self::public_key_from_scalar(&kl);
        Ok(Self::encode_address(&pubkey))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        Self::sign_extended(private_key, message)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Algorand arbitrary message signing with MX domain separator (ARC-60)
        let mut prefixed = Vec::with_capacity(2 + message.len());
        prefixed.extend_from_slice(b"MX");
        prefixed.extend_from_slice(message);
        Self::sign_extended(private_key, &prefixed)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Algorand transaction signing: sign("TX" || msgpack_encoded_tx)
        let mut prefixed = Vec::with_capacity(2 + tx_bytes.len());
        prefixed.extend_from_slice(b"TX");
        prefixed.extend_from_slice(tx_bytes);
        Self::sign_extended(private_key, &prefixed)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Algorand signed transactions are msgpack-encoded:
        //   { "sig": <64-byte Ed25519 signature>, "txn": <transaction object> }
        //
        // tx_bytes is the msgpack-encoded unsigned transaction object.
        // We produce the canonical msgpack encoding ready for algod's
        // POST /v2/transactions endpoint.
        //
        // Hand-encoded msgpack (no external dependency needed):
        //   0x82                          - fixmap with 2 entries
        //   0xa3 0x73 0x69 0x67           - fixstr(3) "sig"
        //   0xc4 0x40 <64 bytes>          - bin8, length 64, signature bytes
        //   0xa3 0x74 0x78 0x6e           - fixstr(3) "txn"
        //   <tx_bytes>                    - raw msgpack transaction object
        //
        // Keys are alphabetically sorted ("sig" < "txn") per Algorand canonical encoding.
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "empty transaction bytes".into(),
            ));
        }

        let mut out = Vec::with_capacity(1 + 4 + 2 + 64 + 4 + tx_bytes.len());
        // fixmap with 2 entries
        out.push(0x82);
        // "sig" key (fixstr length 3)
        out.extend_from_slice(&[0xa3, b's', b'i', b'g']);
        // signature value (bin8, length 64)
        out.extend_from_slice(&[0xc4, 0x40]);
        out.extend_from_slice(&signature.signature);
        // "txn" key (fixstr length 3)
        out.extend_from_slice(&[0xa3, b't', b'x', b'n']);
        // transaction value (raw msgpack bytes, already a valid msgpack object)
        out.extend_from_slice(tx_bytes);

        Ok(out)
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
        assert!(address
            .chars()
            .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));

        // Verify roundtrip: decode address, extract pubkey, re-encode
        let decoded = data_encoding::BASE32_NOPAD
            .decode(address.as_bytes())
            .unwrap();
        assert_eq!(&decoded[..32], pubkey_bytes.as_slice());
        // Last 4 bytes should be checksum
        let hash = sha2::Sha512_256::digest(&pubkey_bytes);
        assert_eq!(&decoded[32..36], &hash[28..32]);
    }

    #[test]
    fn test_address_from_extended_key() {
        // Verify derive_address works with 96-byte extended key
        let mut ext_key = vec![1u8; 96];
        ext_key[0] = 0x40;
        ext_key[31] = 0x40;
        let signer = AvmSigner;
        let address = signer.derive_address(&ext_key).unwrap();
        assert_eq!(address.len(), 58);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = AvmSigner;
        // Build a 96-byte extended key with a valid clamped scalar
        let mut ext_key = [0u8; 96];
        ext_key[0] = 0x40; // Set a valid scalar value in kL
        ext_key[31] = 0x40; // Ensure second-highest bit set
                            // kR (bytes 32..64) and chainCode (bytes 64..96) can be arbitrary for signing
        ext_key[32] = 0xAB; // some kR bytes
        ext_key[63] = 0xCD;

        let message = b"test message for algorand";
        let result = signer.sign(&ext_key, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);

        // Verify using ed25519-dalek
        let pubkey = result.public_key.as_ref().unwrap();
        let verifying_key =
            ed25519_dalek::VerifyingKey::from_bytes(&pubkey.clone().try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(message, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let signer = AvmSigner;
        let mut ext_key = [0u8; 96];
        ext_key[0] = 0x40;
        ext_key[31] = 0x40;
        ext_key[32] = 0xAB;

        let message = b"hello algorand";
        let sig1 = signer.sign(&ext_key, message).unwrap();
        let sig2 = signer.sign(&ext_key, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_different_kr_produces_different_signature() {
        // Verify that kR actually affects the signature (proves we use the real kR)
        let mut ext_key_a = [0u8; 96];
        ext_key_a[0] = 0x40;
        ext_key_a[31] = 0x40;
        ext_key_a[32] = 0x01; // kR byte

        let mut ext_key_b = [0u8; 96];
        ext_key_b[0] = 0x40;
        ext_key_b[31] = 0x40;
        ext_key_b[32] = 0x02; // different kR byte

        let message = b"test message";
        let sig_a = AvmSigner::sign_extended(&ext_key_a, message).unwrap();
        let sig_b = AvmSigner::sign_extended(&ext_key_b, message).unwrap();

        // Same kL means same public key
        assert_eq!(sig_a.public_key, sig_b.public_key);
        // Different kR means different signature
        assert_ne!(sig_a.signature, sig_b.signature);

        // Both must verify
        let pubkey: [u8; 32] = sig_a.public_key.unwrap().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).unwrap();
        use ed25519_dalek::Verifier;
        vk.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&sig_a.signature.try_into().unwrap()),
        )
        .expect("sig_a should verify");
        vk.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&sig_b.signature.try_into().unwrap()),
        )
        .expect("sig_b should verify");
    }

    #[test]
    fn test_invalid_key() {
        let signer = AvmSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
    }

    #[test]
    fn test_sign_transaction_prepends_tx() {
        let signer = AvmSigner;
        let mut ext_key = [0u8; 96];
        ext_key[0] = 0x40;
        ext_key[31] = 0x40;

        let tx_data = b"fake_msgpack_transaction_data";

        // sign_transaction should prepend "TX"
        let result = signer.sign_transaction(&ext_key, tx_data).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Manually sign with "TX" prefix to verify they match
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(b"TX");
        prefixed.extend_from_slice(tx_data);
        let manual = signer.sign(&ext_key, &prefixed).unwrap();
        assert_eq!(result.signature, manual.signature);
    }

    #[test]
    fn test_sign_message_prepends_mx() {
        let signer = AvmSigner;
        let mut ext_key = [0u8; 96];
        ext_key[0] = 0x40;
        ext_key[31] = 0x40;

        let message = b"hello world";

        // sign_message should prepend "MX"
        let result = signer.sign_message(&ext_key, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Manually sign with "MX" prefix to verify they match
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(b"MX");
        prefixed.extend_from_slice(message);
        let manual = signer.sign(&ext_key, &prefixed).unwrap();
        assert_eq!(result.signature, manual.signature);
    }

    #[test]
    fn test_encode_signed_transaction_msgpack() {
        let signer = AvmSigner;
        let sig_bytes = vec![0xABu8; 64];
        let sig_output = SignOutput {
            signature: sig_bytes.clone(),
            recovery_id: None,
            public_key: Some(vec![0u8; 32]),
        };
        // Use a minimal valid msgpack map as the "transaction" bytes
        // 0x81 0xa3 "amt" 0x01 = {"amt": 1}
        let tx_bytes = vec![0x81, 0xa3, b'a', b'm', b't', 0x01];

        let result = signer
            .encode_signed_transaction(&tx_bytes, &sig_output)
            .unwrap();

        // Verify msgpack structure:
        // [0] = 0x82 (fixmap, 2 entries)
        assert_eq!(result[0], 0x82);
        // [1..5] = fixstr(3) "sig"
        assert_eq!(&result[1..5], &[0xa3, b's', b'i', b'g']);
        // [5..7] = bin8 header, length 64
        assert_eq!(&result[5..7], &[0xc4, 0x40]);
        // [7..71] = 64 signature bytes
        assert_eq!(&result[7..71], sig_bytes.as_slice());
        // [71..75] = fixstr(3) "txn"
        assert_eq!(&result[71..75], &[0xa3, b't', b'x', b'n']);
        // [75..] = raw transaction msgpack bytes
        assert_eq!(&result[75..], tx_bytes.as_slice());

        // Total length: 1 + 4 + 2 + 64 + 4 + 6 = 81
        assert_eq!(result.len(), 75 + tx_bytes.len());
    }

    #[test]
    fn test_encode_signed_transaction_rejects_bad_sig() {
        let signer = AvmSigner;
        let sig_output = SignOutput {
            signature: vec![0u8; 32], // wrong length
            recovery_id: None,
            public_key: None,
        };
        assert!(signer
            .encode_signed_transaction(&[0x80], &sig_output)
            .is_err());
    }

    #[test]
    fn test_encode_signed_transaction_rejects_empty_tx() {
        let signer = AvmSigner;
        let sig_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(&[], &sig_output).is_err());
    }
}
