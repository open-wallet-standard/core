use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;

pub struct InitiaSigner {
    hrp: String,
}

impl InitiaSigner {
    pub fn new(hrp: &str) -> Self {
        InitiaSigner {
            hrp: hrp.to_string(),
        }
    }

    pub fn mainnet() -> Self {
        Self::new("init")
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }
}

impl ChainSigner for InitiaSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Initia
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

        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();

        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);
        let address_bytes = &hash[12..];

        let hrp = bech32::Hrp::parse(&self.hrp)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;
        let address = bech32::encode::<bech32::Bech32>(hrp, address_bytes)
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))?;

        Ok(address)
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
        let hash = Sha256::digest(tx_bytes);
        self.sign(private_key, &hash)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let hash = Sha256::digest(message);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/60'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap()
    }

    #[test]
    fn test_address_derivation() {
        let signer = InitiaSigner::mainnet();
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert!(address.starts_with("init1"));

        // Same private key as EVM test — the raw 20-byte address should match
        // EVM: 0x2c7536E3605D9C16a7a3D7b1898e529396a65c23
        // Initia: bech32("init", 0x2c7536e3605d9c16a7a3d7b1898e529396a65c23)
        let (_, addr_bytes) = bech32::decode(&address).unwrap();
        let expected_bytes = hex::decode("2c7536e3605d9c16a7a3d7b1898e529396a65c23").unwrap();
        assert_eq!(addr_bytes, expected_bytes);
    }

    #[test]
    fn test_sign_roundtrip() {
        let signer = InitiaSigner::mainnet();
        let hash = Sha256::digest(b"test message");
        let result = signer.sign(&test_privkey(), &hash).unwrap();

        assert_eq!(result.signature.len(), 65);
        assert!(result.recovery_id.is_some());

        let signing_key = SigningKey::from_slice(&test_privkey()).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r_bytes: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes).unwrap();

        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        verifying_key
            .verify_prehash(&hash, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn test_derivation_path() {
        let signer = InitiaSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/60'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/44'/60'/0'/0/3");
    }

    #[test]
    fn test_chain_properties() {
        let signer = InitiaSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Initia);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 60);
    }

    #[test]
    fn test_deterministic() {
        let signer = InitiaSigner::mainnet();
        let addr1 = signer.derive_address(&test_privkey()).unwrap();
        let addr2 = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_invalid_key_rejection() {
        let signer = InitiaSigner::mainnet();
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_custom_hrp() {
        let signer = InitiaSigner::new("custom");
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert!(address.starts_with("custom1"));

        let mainnet_signer = InitiaSigner::mainnet();
        let mainnet_addr = mainnet_signer.derive_address(&test_privkey()).unwrap();

        let (_, custom_bytes) = bech32::decode(&address).unwrap();
        let (_, mainnet_bytes) = bech32::decode(&mainnet_addr).unwrap();
        assert_eq!(custom_bytes, mainnet_bytes);
    }
}
