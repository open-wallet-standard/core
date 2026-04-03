use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha3::{Digest, Keccak256};

/// EVM (Ethereum-compatible) chain signer.
pub struct EvmSigner;

impl EvmSigner {
    /// Derive an EIP-55 checksummed address from a private key.
    fn eip55_checksum(address_hex: &str) -> String {
        // address_hex should be 40 hex chars (no 0x prefix)
        let lower = address_hex.to_lowercase();
        let hash = Keccak256::digest(lower.as_bytes());
        let hash_hex = hex::encode(hash);

        let mut checksummed = String::with_capacity(42);
        checksummed.push_str("0x");
        for (i, c) in lower.chars().enumerate() {
            if c.is_ascii_digit() {
                checksummed.push(c);
            } else {
                // If the corresponding hex nibble of the hash is >= 8, uppercase
                let nibble = u8::from_str_radix(&hash_hex[i..i + 1], 16).unwrap_or(0);
                if nibble >= 8 {
                    checksummed.push(c.to_ascii_uppercase());
                } else {
                    checksummed.push(c);
                }
            }
        }
        checksummed
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|_| SignerError::InvalidPrivateKey("key parsing failed".into()))
    }

    /// Sign EIP-712 typed structured data.
    pub fn sign_typed_data(
        &self,
        private_key: &[u8],
        typed_data_json: &str,
    ) -> Result<SignOutput, SignerError> {
        let typed_data = crate::eip712::parse_typed_data(typed_data_json)?;
        let hash = crate::eip712::hash_typed_data(&typed_data)?;
        let mut output = self.sign(private_key, &hash)?;

        // EIP-712 convention: v = 27 + recovery_id
        if let Some(rid) = output.recovery_id {
            let v = rid + 27;
            output.signature[64] = v;
            output.recovery_id = Some(v);
        }
        Ok(output)
    }
}

impl ChainSigner for EvmSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Evm
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        60
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key (65 bytes: 0x04 || x || y)
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();

        // Keccak256 hash of the public key (skip the 0x04 prefix byte)
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);

        // Take last 20 bytes
        let address_bytes = &hash[12..];
        let address_hex = hex::encode(address_bytes);

        Ok(Self::eip55_checksum(&address_hex))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte prehash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();

        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&r_bytes);
        sig_bytes.extend_from_slice(&s_bytes);
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // EVM transaction signing: keccak256 hash of the unsigned tx envelope
        let hash = Keccak256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 65 {
            return Err(SignerError::InvalidTransaction(
                "expected 65-byte signature (r || s || v)".into(),
            ));
        }

        let v = signature.signature[64];
        let r: [u8; 32] = signature.signature[..32]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("bad r".into()))?;
        let s: [u8; 32] = signature.signature[32..64]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("bad s".into()))?;

        crate::rlp::encode_signed_typed_tx(tx_bytes, v, &r, &s)
            .map_err(|e| SignerError::InvalidTransaction(e.to_string()))
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // EIP-191 personal sign prefix
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(message);

        let hash = Keccak256::digest(&prefixed);
        let mut output = self.sign(private_key, &hash)?;

        // EIP-191 convention: v = 27 + recovery_id
        if let Some(rid) = output.recovery_id {
            let v = rid + 27;
            output.signature[64] = v;
            output.recovery_id = Some(v);
        }
        Ok(output)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/60'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;

    #[test]
    fn test_known_privkey_to_address() {
        // Well-known test vector (web3.js documentation)
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(address, "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
    }

    #[test]
    fn test_eip55_checksum() {
        // Test the checksum independently
        let addr = "2c7536e3605d9c16a7a3d7b1898e529396a65c23";
        let checksummed = EvmSigner::eip55_checksum(addr);
        assert_eq!(checksummed, "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23");
    }

    #[test]
    fn test_sign_and_recover_roundtrip() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;

        let message_hash = Keccak256::digest(b"test message");
        let result = signer.sign(&privkey, &message_hash).unwrap();

        assert_eq!(result.signature.len(), 65);
        assert!(result.recovery_id.is_some());

        // Verify the signature
        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();

        let r_bytes: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes).unwrap();

        verifying_key
            .verify_prehash(&message_hash, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn test_sign_message_eip191() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let result = signer.sign_message(&privkey, b"Hello World").unwrap();
        assert_eq!(result.signature.len(), 65);
    }

    #[test]
    fn test_derivation_path() {
        let signer = EvmSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(signer.default_derivation_path(5), "m/44'/60'/0'/0/5");
    }

    #[test]
    fn test_invalid_key_rejection() {
        let signer = EvmSigner;
        let bad_key = vec![0u8; 16]; // Too short
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_chain_properties() {
        let signer = EvmSigner;
        assert_eq!(signer.chain_type(), ChainType::Evm);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 60);
    }

    #[test]
    fn test_sign_rejects_non_32_byte_hash() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let result = signer.sign(&privkey, b"too short");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_message_v_byte_27_or_28() {
        // EIP-191 personal_sign convention: v must be 27 or 28
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let result = signer.sign_message(&privkey, b"Hello World").unwrap();
        let v = result.signature[64];
        assert!(
            v == 27 || v == 28,
            "EIP-191 personal_sign v byte should be 27 or 28, got {v}"
        );
    }

    #[test]
    fn test_sign_message_recovery_id_matches_v() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let result = signer.sign_message(&privkey, b"test recovery id").unwrap();
        let v = result.signature[64];
        let recovery_id = result.recovery_id.unwrap();
        assert_eq!(
            v, recovery_id,
            "v byte in signature should match recovery_id field"
        );
        assert!(
            recovery_id == 27 || recovery_id == 28,
            "recovery_id for EIP-191 should be 27 or 28, got {recovery_id}"
        );
    }

    #[test]
    fn test_sign_message_verifiable_with_v_27_28() {
        // Verify signature is valid AND v is correct
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let result = signer.sign_message(&privkey, b"verify me").unwrap();

        // Signature should verify
        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r_bytes: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes).unwrap();

        let prefix = format!("\x19Ethereum Signed Message:\n{}", b"verify me".len());
        let mut prefixed = Vec::new();
        prefixed.extend_from_slice(prefix.as_bytes());
        prefixed.extend_from_slice(b"verify me");
        let hash = Keccak256::digest(&prefixed);

        verifying_key
            .verify_prehash(&hash, &sig)
            .expect("signature should verify");

        // AND v must be 27 or 28
        let v = result.signature[64];
        assert!(v == 27 || v == 28, "v should be 27 or 28, got {v}");
    }

    #[test]
    fn test_deterministic_address() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_encode_signed_transaction_eip1559() {
        use crate::rlp;

        // Build a minimal unsigned EIP-1559 transaction
        let items: Vec<u8> = [
            rlp::encode_bytes(&[1]),          // chain_id = 1
            rlp::encode_bytes(&[]),           // nonce = 0
            rlp::encode_bytes(&[1]),          // maxPriorityFeePerGas = 1
            rlp::encode_bytes(&[100]),        // maxFeePerGas = 100
            rlp::encode_bytes(&[0x52, 0x08]), // gasLimit = 21000
            rlp::encode_bytes(&[0xDE, 0xAD]), // to (truncated for test)
            rlp::encode_bytes(&[]),           // value = 0
            rlp::encode_bytes(&[]),           // data = empty
            rlp::encode_list(&[]),            // accessList = empty
        ]
        .concat();

        let mut unsigned_tx = vec![0x02];
        unsigned_tx.extend_from_slice(&rlp::encode_list(&items));

        // Sign it
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let output = signer.sign_transaction(&privkey, &unsigned_tx).unwrap();

        // Encode the signed transaction
        let signed_tx = signer
            .encode_signed_transaction(&unsigned_tx, &output)
            .unwrap();

        // Verify structure
        assert_eq!(signed_tx[0], 0x02, "should preserve type byte");
        assert!(
            signed_tx.len() > unsigned_tx.len(),
            "signed tx should be larger than unsigned tx"
        );
    }

    #[test]
    fn test_address_starts_with_0x() {
        let privkey =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
                .unwrap();
        let signer = EvmSigner;
        let addr = signer.derive_address(&privkey).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }
}
