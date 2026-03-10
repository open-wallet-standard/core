pub mod chains;
pub mod crypto;
pub mod curve;
pub mod eip712;
pub mod hd;
pub mod key_cache;
pub mod mnemonic;
pub mod process_hardening;
pub mod traits;
pub mod zeroizing;

pub use chains::signer_for_chain;
pub use crypto::{decrypt, encrypt, CipherParams, CryptoEnvelope, CryptoError, KdfParams};
pub use curve::Curve;
pub use hd::HdDeriver;
pub use mnemonic::{Mnemonic, MnemonicStrength};
pub use traits::{ChainSigner, SignOutput, SignerError};
pub use zeroizing::SecretBytes;

use key_cache::KeyCache;
use std::sync::OnceLock;
use std::time::Duration;

static GLOBAL_KEY_CACHE: OnceLock<KeyCache> = OnceLock::new();

/// Returns the process-wide key cache (5s TTL, max 32 entries).
pub fn global_key_cache() -> &'static KeyCache {
    GLOBAL_KEY_CACHE.get_or_init(|| KeyCache::new(Duration::from_secs(5), 32))
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use digest::Digest;
    use lws_core::ChainType;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn derive_address_for_chain(
        mnemonic: &Mnemonic,
        chain: ChainType,
    ) -> String {
        let signer = signer_for_chain(chain);
        let curve = signer.curve();
        let path = signer.default_derivation_path(0);

        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve).unwrap();
        signer.derive_address(key.expose()).unwrap()
    }

    #[test]
    fn test_full_pipeline_evm() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Evm);
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_full_pipeline_solana() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Solana);
        // Base58 encoded ed25519 pubkey
        assert!(!address.is_empty());
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_full_pipeline_bitcoin() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Bitcoin);
        assert!(address.starts_with("bc1"));
    }

    #[test]
    fn test_full_pipeline_cosmos() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Cosmos);
        assert!(address.starts_with("cosmos1"));
    }

    #[test]
    fn test_full_pipeline_tron() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Tron);
        assert!(address.starts_with('T'));
        assert_eq!(address.len(), 34);
    }

    #[test]
    fn test_full_pipeline_ton() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Ton);
        assert!(address.starts_with("EQ"), "TON bounceable address should start with EQ, got: {}", address);
        assert_eq!(address.len(), 48);
    }

    #[test]
    fn test_cross_chain_different_addresses() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let evm_addr = derive_address_for_chain(&mnemonic, ChainType::Evm);
        let sol_addr = derive_address_for_chain(&mnemonic, ChainType::Solana);
        let btc_addr = derive_address_for_chain(&mnemonic, ChainType::Bitcoin);
        let cosmos_addr = derive_address_for_chain(&mnemonic, ChainType::Cosmos);
        let tron_addr = derive_address_for_chain(&mnemonic, ChainType::Tron);
        let ton_addr = derive_address_for_chain(&mnemonic, ChainType::Ton);

        // All addresses should be different
        let addrs = vec![&evm_addr, &sol_addr, &btc_addr, &cosmos_addr, &tron_addr, &ton_addr];
        for i in 0..addrs.len() {
            for j in (i + 1)..addrs.len() {
                assert_ne!(addrs[i], addrs[j], "addresses should differ");
            }
        }
    }

    #[test]
    fn test_deterministic_across_calls() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let addr1 = derive_address_for_chain(&mnemonic, ChainType::Evm);
        let addr2 = derive_address_for_chain(&mnemonic, ChainType::Evm);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_roundtrip_all_secp256k1_chains() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        for chain in [ChainType::Evm, ChainType::Bitcoin, ChainType::Cosmos, ChainType::Tron] {
            let signer = signer_for_chain(chain);
            let path = signer.default_derivation_path(0);
            let key =
                HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Secp256k1).unwrap();

            // Create a dummy 32-byte hash
            let hash = sha2::Sha256::digest(b"test transaction data");
            let result = signer.sign(key.expose(), &hash).unwrap();
            assert!(!result.signature.is_empty());
            assert!(result.recovery_id.is_some());
        }
    }

    #[test]
    fn test_sign_roundtrip_ed25519_chains() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        for chain in [ChainType::Solana, ChainType::Ton] {
            let signer = signer_for_chain(chain);
            let path = signer.default_derivation_path(0);
            let key =
                HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519).unwrap();

            let result = signer.sign(key.expose(), b"test message").unwrap();
            assert_eq!(result.signature.len(), 64);
            assert!(result.recovery_id.is_none());
        }
    }

    #[test]
    fn test_signer_for_chain_registry() {
        // Verify all chain types are supported
        for chain in [
            ChainType::Evm,
            ChainType::Solana,
            ChainType::Bitcoin,
            ChainType::Cosmos,
            ChainType::Tron,
            ChainType::Ton,
        ] {
            let signer = signer_for_chain(chain);
            assert_eq!(signer.chain_type(), chain);
        }
    }
}
