use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use lws_core::ChainType;
use sha2::{Digest, Sha256};

/// TON chain signer (Ed25519, wallet v4r2 addresses).
pub struct TonSigner;

/// Default subwallet_id for wallet v4r2.
const DEFAULT_SUBWALLET_ID: u32 = 698983191;

/// Wallet v4r2 code cell hash (SHA256 of the cell representation).
/// Verified against @ton/ton npm package v15.
const WALLET_V4R2_CODE_HASH: [u8; 32] = [
    0xfe, 0xb5, 0xff, 0x68, 0x20, 0xe2, 0xff, 0x0d, 0x94, 0x83, 0xe7, 0xe0, 0xd6, 0x2c, 0x81,
    0x7d, 0x84, 0x67, 0x89, 0xfb, 0x4a, 0xe5, 0x80, 0xc8, 0x78, 0x86, 0x6d, 0x95, 0x9d, 0xab,
    0xd5, 0xc0,
];

/// Wallet v4r2 code cell depth.
const WALLET_V4R2_CODE_DEPTH: u16 = 7;

impl TonSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| {
                SignerError::InvalidPrivateKey(format!(
                    "expected 32 bytes, got {}",
                    private_key.len()
                ))
            })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    /// Compute the data cell hash for wallet v4r2 initial state.
    /// Data cell: seqno(0, 32b) + subwallet_id(32b) + public_key(256b) = 320 bits, 0 refs.
    fn data_cell_hash(public_key: &[u8; 32]) -> [u8; 32] {
        let d1: u8 = 0; // 0 refs
        let d2: u8 = 80; // ceil(320/8) + floor(320/8) = 40 + 40

        let mut repr = Vec::with_capacity(42);
        repr.push(d1);
        repr.push(d2);
        repr.extend_from_slice(&0u32.to_be_bytes()); // seqno = 0
        repr.extend_from_slice(&DEFAULT_SUBWALLET_ID.to_be_bytes());
        repr.extend_from_slice(public_key);

        Sha256::digest(&repr).into()
    }

    /// Compute the StateInit cell hash.
    /// StateInit: 5 bits (00110) = split_depth(0) special(0) code(1) data(1) library(0), 2 refs.
    fn state_init_hash(code_hash: &[u8; 32], code_depth: u16, data_hash: &[u8; 32]) -> [u8; 32] {
        let d1: u8 = 2; // 2 refs
        let d2: u8 = 1; // ceil(5/8) + floor(5/8) = 1 + 0

        let mut repr = Vec::with_capacity(3 + 4 + 64);
        repr.push(d1);
        repr.push(d2);
        repr.push(0x34); // 00110 + completion tag '100' = 0b00110100

        // Depths (2 bytes big-endian each)
        repr.push((code_depth >> 8) as u8);
        repr.push(code_depth as u8);
        repr.push(0); // data cell depth = 0
        repr.push(0);

        // Hashes
        repr.extend_from_slice(code_hash);
        repr.extend_from_slice(data_hash);

        Sha256::digest(&repr).into()
    }

    /// Encode a TON user-friendly address (base64url with CRC16).
    fn encode_address(workchain: i8, hash: &[u8; 32], bounceable: bool) -> String {
        use base64::Engine;
        let tag: u8 = if bounceable { 0x11 } else { 0x51 };

        let mut addr = Vec::with_capacity(36);
        addr.push(tag);
        addr.push(workchain as u8);
        addr.extend_from_slice(hash);

        let crc = crc16_ccitt(&addr);
        addr.push((crc >> 8) as u8);
        addr.push(crc as u8);

        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&addr)
    }
}

impl ChainSigner for TonSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Ton
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        607
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: &[u8; 32] = verifying_key.as_bytes();

        let data_hash = Self::data_cell_hash(pubkey_bytes);
        let state_hash =
            Self::state_init_hash(&WALLET_V4R2_CODE_HASH, WALLET_V4R2_CODE_DEPTH, &data_hash);

        Ok(Self::encode_address(0, &state_hash, true))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        self.sign(private_key, tx_bytes)
    }

    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/607'/{}'/0'", index)
    }
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::Verifier;

    fn test_privkey() -> Vec<u8> {
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
    }

    #[test]
    fn test_code_hash_constant() {
        assert_eq!(
            hex::encode(WALLET_V4R2_CODE_HASH),
            "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0"
        );
    }

    #[test]
    fn test_data_cell_hash_matches_ton_core() {
        // Null pubkey data cell hash verified against @ton/ton npm package
        let null_pubkey = [0u8; 32];
        let hash = TonSigner::data_cell_hash(&null_pubkey);
        assert_eq!(
            hex::encode(hash),
            "a8ee56af92eb3de1a48c2a001803c2c30ed0d601a766265d6fd721813022d782"
        );
    }

    #[test]
    fn test_known_address() {
        // Address verified against @ton/ton WalletContractV4.create()
        // Private key: 9d61b19d... -> Public key: d75a9801...
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(
            address,
            "EQDNrJfJFisuFBrURjgosqcO_fh2K5foNWPzUr7PkC6Ipopv"
        );
    }

    #[test]
    fn test_address_format() {
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(address.len(), 48, "TON address should be 48 chars");
        assert!(address.starts_with("EQ"), "bounceable workchain-0 address should start with EQ");
    }

    #[test]
    fn test_address_decodes_to_valid_structure() {
        let signer = TonSigner;
        let address = signer.derive_address(&test_privkey()).unwrap();

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&address)
            .unwrap();
        assert_eq!(decoded.len(), 36);
        assert_eq!(decoded[0], 0x11); // bounceable tag
        assert_eq!(decoded[1], 0x00); // workchain 0

        let crc = crc16_ccitt(&decoded[..34]);
        assert_eq!(decoded[34], (crc >> 8) as u8);
        assert_eq!(decoded[35], crc as u8);
    }

    #[test]
    fn test_deterministic_address() {
        let signer = TonSigner;
        let addr1 = signer.derive_address(&test_privkey()).unwrap();
        let addr2 = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey = test_privkey();
        let signer = TonSigner;
        let message = b"test message for ton";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_no_recovery_id() {
        let signer = TonSigner;
        let result = signer.sign(&test_privkey(), b"msg").unwrap();
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn test_derivation_path() {
        let signer = TonSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/607'/0'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/607'/1'/0'");
    }

    #[test]
    fn test_chain_properties() {
        let signer = TonSigner;
        assert_eq!(signer.chain_type(), ChainType::Ton);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 607);
    }

    #[test]
    fn test_invalid_key() {
        let signer = TonSigner;
        let bad_key = vec![0u8; 16];
        assert!(signer.derive_address(&bad_key).is_err());
    }

    #[test]
    fn test_crc16() {
        let data = b"123456789";
        assert_eq!(crc16_ccitt(data), 0x31C3);
    }
}
