use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;

/// Solana chain signer (Ed25519).
pub struct SolanaSigner;

impl SolanaSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for SolanaSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Solana
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        501
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(bs58::encode(verifying_key.as_bytes()).into_string())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Ed25519 signs raw message bytes directly (no prehashing).
        // Callers passing a full serialized Solana transaction (with signature
        // slots) must call extract_signable_bytes() first.
        self.sign(private_key, tx_bytes)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        // Solana serialized transaction format:
        // [compact-u16: num_signatures] [64-byte signatures...] [message...]
        // Return only the message portion.
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        let num_sigs = tx_bytes[0] as usize;
        let message_start = 1 + num_sigs * 64;
        if tx_bytes.len() <= message_start {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }
        Ok(&tx_bytes[message_start..])
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Solana serialized transaction format:
        // [compact-u16: num_signatures] [64-byte signatures...] [message...]
        // Replace the first 64-byte zero-signature with the real signature.
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }

        // First byte is compact-u16 for number of signatures (typically 0x01)
        let num_sigs = tx_bytes[0] as usize;
        if num_sigs == 0 {
            return Err(SignerError::InvalidTransaction(
                "transaction has no signature slots".into(),
            ));
        }
        let sigs_end = 1 + num_sigs * 64;
        if tx_bytes.len() < sigs_end {
            return Err(SignerError::InvalidTransaction(
                "transaction too short for declared signature slots".into(),
            ));
        }

        let mut signed = tx_bytes.to_vec();
        // Replace first signature slot (bytes 1..65)
        signed[1..65].copy_from_slice(&signature.signature);
        Ok(signed)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Solana doesn't use a special prefix for message signing
        self.sign(private_key, message)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/501'/{}'/0'", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_ed25519_rfc8032_vector1() {
        // RFC 8032 Test Vector 1
        let secret =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let expected_pubkey =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();

        let signing_key = SigningKey::from_bytes(&secret.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        assert_eq!(verifying_key.as_bytes(), expected_pubkey.as_slice());
    }

    #[test]
    fn test_base58_address() {
        let signer = SolanaSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let address = signer.derive_address(&privkey).unwrap();
        // Base58 encoded ed25519 public key
        assert!(!address.is_empty());
        // Verify it decodes back to 32 bytes
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;

        let message = b"test message for solana";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Verify
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"hello";

        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_no_recovery_id() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let result = signer.sign(&privkey, b"msg").unwrap();
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn test_derivation_path() {
        let signer = SolanaSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/501'/0'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/501'/1'/0'");
    }

    #[test]
    fn test_chain_properties() {
        let signer = SolanaSigner;
        assert_eq!(signer.chain_type(), ChainType::Solana);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 501);
    }

    #[test]
    fn test_invalid_key() {
        let signer = SolanaSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_extract_signable_bytes() {
        let signer = SolanaSigner;

        // Build a minimal Solana serialized tx: [1 sig slot] [64 zero bytes] [message]
        let mut tx_bytes = vec![0x01]; // 1 signature slot
        tx_bytes.extend_from_slice(&[0u8; 64]); // placeholder zero signature
        tx_bytes.extend_from_slice(b"fake_message_payload");

        let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
        assert_eq!(signable, b"fake_message_payload");
    }

    #[test]
    fn test_extract_signable_bytes_errors() {
        let signer = SolanaSigner;

        // Empty input
        assert!(signer.extract_signable_bytes(&[]).is_err());

        // Too short for declared signature slots
        let short = vec![0x01, 0x00]; // claims 1 sig slot but only 1 byte after header
        assert!(signer.extract_signable_bytes(&short).is_err());
    }

    #[test]
    fn test_sign_transaction_is_passthrough() {
        // sign_transaction signs whatever bytes it receives (caller strips headers)
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"fake_message_payload";

        let via_sign = signer.sign(&privkey, message).unwrap();
        let via_sign_tx = signer.sign_transaction(&privkey, message).unwrap();
        assert_eq!(via_sign.signature, via_sign_tx.signature);
    }

    #[test]
    fn test_full_sign_and_encode_pipeline() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;

        // Build a minimal Solana serialized tx: [1 sig slot] [64 zero bytes] [message]
        let mut tx_bytes = vec![0x01]; // 1 signature slot
        tx_bytes.extend_from_slice(&[0u8; 64]); // placeholder zero signature
        tx_bytes.extend_from_slice(b"fake_message_payload");

        // Pipeline: extract → sign → encode (mirrors sign_and_send in ops.rs)
        let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let signed = signer
            .encode_signed_transaction(&tx_bytes, &output)
            .unwrap();

        // The signature should be spliced in at bytes 1..65
        assert_eq!(&signed[1..65], &output.signature[..]);
        // The rest of the tx should be unchanged
        assert_eq!(&signed[65..], &tx_bytes[65..]);
        assert_eq!(signed.len(), tx_bytes.len());

        // Verify the signature is over the message portion
        let message = &tx_bytes[65..];
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(message, &sig)
            .expect("signature should verify against the message portion only");
    }

    #[test]
    fn test_sign_message_same_as_sign() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = SolanaSigner;
        let message = b"hello solana";
        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }
}
