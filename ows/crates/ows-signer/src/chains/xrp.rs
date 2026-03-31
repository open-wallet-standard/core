use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

pub struct XrpSigner;

impl XrpSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key).map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }
    fn account_id(private_key: &[u8]) -> Result<Vec<u8>, SignerError> {
        let sk = Self::signing_key(private_key)?;
        let pk = sk.verifying_key().to_encoded_point(true);
        let sha = Sha256::digest(pk.as_bytes());
        Ok(Ripemd160::digest(&sha).to_vec())
    }
}

impl ChainSigner for XrpSigner {
    fn chain_type(&self) -> ChainType { ChainType::Xrp }
    fn curve(&self) -> Curve { Curve::Secp256k1 }
    fn coin_type(&self) -> u32 { 144 }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let id = Self::account_id(private_key)?;
        let mut payload = vec![0x00u8];
        payload.extend_from_slice(&id);
        Ok(bs58::encode(&payload).with_alphabet(bs58::Alphabet::RIPPLE).with_check().into_string())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 { return Err(SignerError::InvalidMessage(format!("expected 32-byte hash, got {}", message.len()))); }
        let sk = Self::signing_key(private_key)?;
        let (sig, rid) = sk.sign_prehash_recoverable(message).map_err(|e| SignerError::SigningFailed(e.to_string()))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(rid.to_byte());
        Ok(SignOutput { signature: out, recovery_id: Some(rid.to_byte()), public_key: None })
    }

    fn sign_transaction(&self, private_key: &[u8], tx_bytes: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, &Sha256::digest(tx_bytes))
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, &Sha256::digest(message))
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/144'/0'/0/{index}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_privkey() -> Vec<u8> { hex::decode("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").unwrap() }

    #[test] fn test_address_starts_with_r() { assert!(XrpSigner.derive_address(&test_privkey()).unwrap().starts_with('r')); }
    #[test] fn test_address_length() { let a = XrpSigner.derive_address(&test_privkey()).unwrap(); assert!(a.len() >= 25 && a.len() <= 35); }
    #[test] fn test_base58check_roundtrip() {
        let a = XrpSigner.derive_address(&test_privkey()).unwrap();
        let d = bs58::decode(&a).with_alphabet(bs58::Alphabet::RIPPLE).with_check(None).into_vec().unwrap();
        assert_eq!(d[0], 0x00); assert_eq!(d.len(), 21);
    }
    #[test] fn test_derivation_path() { assert_eq!(XrpSigner.default_derivation_path(0), "m/44'/144'/0'/0/0"); }
    #[test] fn test_chain_properties() { assert_eq!(XrpSigner.chain_type(), ChainType::Xrp); assert_eq!(XrpSigner.coin_type(), 144); }
    #[test] fn test_deterministic() { assert_eq!(XrpSigner.derive_address(&test_privkey()).unwrap(), XrpSigner.derive_address(&test_privkey()).unwrap()); }
}
