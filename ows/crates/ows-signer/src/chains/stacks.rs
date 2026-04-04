use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha2::{Digest, Sha256, Sha512_256};

/// Stacks blockchain signer (Bitcoin L2).
/// Coin type: 5757 (SLIP-44)
/// Derivation: m/44'/5757'/0'/0/{index}
/// Address format: c32check encoding (SP... mainnet, ST... testnet)
pub struct StacksSigner {
    mainnet: bool,
}

impl StacksSigner {
    pub fn mainnet() -> Self {
        StacksSigner { mainnet: true }
    }

    pub fn testnet() -> Self {
        StacksSigner { mainnet: false }
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    fn hash160(data: &[u8]) -> Vec<u8> {
        use ripemd::Ripemd160;
        let sha256 = Sha256::digest(data);
        let ripemd = Ripemd160::digest(sha256);
        ripemd.to_vec()
    }

    fn c32check_encode(version: u8, data: &[u8]) -> String {
        const C32_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut check_input = vec![version];
        check_input.extend_from_slice(data);
        let first = Sha256::digest(&check_input);
        let second = Sha256::digest(first);
        let checksum = &second[..4];

        let mut payload = vec![version];
        payload.extend_from_slice(data);
        payload.extend_from_slice(checksum);

        let mut result = Vec::new();
        let mut carry: u32 = 0;
        let mut carry_bits: u32 = 0;

        for byte in payload.iter().rev() {
            carry |= (*byte as u32) << carry_bits;
            carry_bits += 8;
            while carry_bits >= 5 {
                result.push(C32_ALPHABET[(carry & 0x1f) as usize]);
                carry >>= 5;
                carry_bits -= 5;
            }
        }
        if carry_bits > 0 {
            result.push(C32_ALPHABET[(carry & 0x1f) as usize]);
        }

        result.reverse();
        let encoded = String::from_utf8(result).unwrap_or_default();
        let version_char = C32_ALPHABET[(version & 0x1f) as usize] as char;
        format!("S{}{}", version_char, encoded)
    }
}

impl ChainSigner for StacksSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stacks
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        5757
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();
        let hash = Self::hash160(pubkey_bytes);
        let version = if self.mainnet { 22u8 } else { 26u8 };
        Ok(Self::c32check_encode(version, &hash))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }
        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
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
        let hash = Sha512_256::digest(tx_bytes);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);
        self.sign(private_key, &hash_bytes)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let hash = Sha512_256::digest(message);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);
        self.sign(private_key, &hash_bytes)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/5757'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_mainnet_address_prefix() {
        let signer = StacksSigner::mainnet();
        let addr = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            addr.starts_with('S'),
            "mainnet address should start with S, got: {addr}"
        );
    }

    #[test]
    fn test_testnet_address_prefix() {
        let signer = StacksSigner::testnet();
        let addr = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            addr.starts_with('S'),
            "testnet address should start with S, got: {addr}"
        );
    }

    #[test]
    fn test_mainnet_testnet_differ() {
        let privkey = test_privkey();
        let mainnet = StacksSigner::mainnet().derive_address(&privkey).unwrap();
        let testnet = StacksSigner::testnet().derive_address(&privkey).unwrap();
        assert_ne!(mainnet, testnet);
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_transaction_uses_sha512_256() {
        let signer = StacksSigner::mainnet();
        let privkey = test_privkey();
        let tx = b"fake stacks transaction bytes";
        let result = signer.sign_transaction(&privkey, tx);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().signature.len(), 65);
    }

    #[test]
    fn test_derivation_path() {
        let signer = StacksSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/5757'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/44'/5757'/0'/0/3");
    }

    #[test]
    fn test_chain_properties() {
        let signer = StacksSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Stacks);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 5757);
    }
}
