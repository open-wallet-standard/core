pub mod chains;
pub mod crypto;
pub mod curve;
pub mod eip712;
pub mod hd;
pub mod key_cache;
pub mod mnemonic;
pub mod process_hardening;
pub mod rlp;
pub mod traits;
pub mod zeroizing;

pub use chains::signer_for_chain;
pub use crypto::{
    decrypt, encrypt, encrypt_with_hkdf, CipherParams, CryptoEnvelope, CryptoError, HkdfKdfParams,
    KdfParams, KdfParamsVariant,
};
pub use curve::Curve;
pub use hd::{ed25519_scalar_mult_base_noclamp, HdDeriver};
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
    use ows_core::ChainType;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn derive_address_for_chain(mnemonic: &Mnemonic, chain: ChainType) -> String {
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
        assert!(
            address.starts_with("UQ"),
            "TON non-bounceable address should start with UQ, got: {}",
            address
        );
        assert_eq!(address.len(), 48);
    }

    #[test]
    fn test_full_pipeline_spark() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Spark);
        assert!(
            address.starts_with("spark:"),
            "Spark address should start with spark:, got: {}",
            address
        );
    }

    #[test]
    fn test_full_pipeline_filecoin() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Filecoin);
        assert!(
            address.starts_with("f1"),
            "Filecoin address should start with f1, got: {}",
            address
        );
    }

    #[test]
    fn test_full_pipeline_xrpl() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Xrpl);
        assert!(
            address.starts_with('r'),
            "XRPL address must start with 'r', got: {}",
            address
        );
        assert!(
            address.len() >= 25 && address.len() <= 34,
            "XRPL address length must be 25-34, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_spark_uses_bitcoin_derivation_path() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let btc_signer = signer_for_chain(ChainType::Bitcoin);
        let spark_signer = signer_for_chain(ChainType::Spark);

        // Same derivation path
        assert_eq!(
            btc_signer.default_derivation_path(0),
            spark_signer.default_derivation_path(0),
        );

        // Same derived key
        let btc_key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &btc_signer.default_derivation_path(0),
            Curve::Secp256k1,
        )
        .unwrap();
        let spark_key = HdDeriver::derive_from_mnemonic(
            &mnemonic,
            "",
            &spark_signer.default_derivation_path(0),
            Curve::Secp256k1,
        )
        .unwrap();
        assert_eq!(btc_key.expose(), spark_key.expose());
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
        let spark_addr = derive_address_for_chain(&mnemonic, ChainType::Spark);
        let fil_addr = derive_address_for_chain(&mnemonic, ChainType::Filecoin);
        let xrpl_addr = derive_address_for_chain(&mnemonic, ChainType::Xrpl);
        let algo_addr = derive_address_for_chain(&mnemonic, ChainType::Avm);

        // All addresses should be different
        let addrs = [
            &evm_addr,
            &sol_addr,
            &btc_addr,
            &cosmos_addr,
            &tron_addr,
            &ton_addr,
            &spark_addr,
            &fil_addr,
            &xrpl_addr,
            &algo_addr,
        ];
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

        for chain in [
            ChainType::Evm,
            ChainType::Bitcoin,
            ChainType::Cosmos,
            ChainType::Tron,
            ChainType::Spark,
            ChainType::Filecoin,
        ] {
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
    fn test_full_pipeline_algorand() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let address = derive_address_for_chain(&mnemonic, ChainType::Avm);
        // Algorand address: 58 uppercase base32 characters
        assert_eq!(address.len(), 58);
        assert!(
            address
                .chars()
                .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)),
            "Algorand address should be base32, got: {}",
            address
        );
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
    fn test_sign_roundtrip_bip32_ed25519_chains() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let signer = signer_for_chain(ChainType::Avm);
        let path = signer.default_derivation_path(0);
        let key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519Bip32).unwrap();

        let result = signer.sign(key.expose(), b"test message").unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
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
            ChainType::Spark,
            ChainType::Filecoin,
            ChainType::Xrpl,
            ChainType::Nano,
            ChainType::Avm,
        ] {
            let signer = signer_for_chain(chain);
            assert_eq!(signer.chain_type(), chain);
        }
    }

    // BIP32-Ed25519 Peikert (g=9) test vectors
    // Verified against xHD-Wallet-API-ts (algorandfoundation/xHD-Wallet-API-ts)
    // All public keys match the passing TypeScript test suite (122/122 tests).

    const ALGO_MNEMONIC: &str = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice";

    fn algo_seed() -> SecretBytes {
        Mnemonic::from_phrase(ALGO_MNEMONIC).unwrap().to_seed("")
    }

    /// Helper: derive BIP32-Ed25519 key and return the public key hex.
    fn derive_algo_pubkey(seed: &SecretBytes, path: &str) -> String {
        let key = HdDeriver::derive(seed.expose(), path, Curve::Ed25519Bip32).unwrap();
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        hex::encode(hd::ed25519_scalar_mult_base_noclamp(&scalar))
    }

    #[test]
    fn test_algo_root_key() {
        let seed = algo_seed();
        let root = hd::bip32_ed25519_from_seed(seed.expose()).unwrap();
        assert_eq!(
            hex::encode(&root),
            "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f46\
             94592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05\
             796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946"
        );
    }

    #[test]
    fn test_algo_address_keys() {
        let seed = algo_seed();
        // Address context: m/44'/283'/account'/0/key_index (Peikert g=9)
        let vectors: &[(&str, &str)] = &[
            (
                "m/44'/283'/0'/0/0",
                "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9",
            ),
            (
                "m/44'/283'/0'/0/1",
                "5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519",
            ),
            (
                "m/44'/283'/0'/0/2",
                "00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3",
            ),
            (
                "m/44'/283'/1'/0/0",
                "358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9",
            ),
            (
                "m/44'/283'/2'/0/1",
                "1f0f75fbbca12b22523973191061b2f96522740e139a3420c730717ac5b0dfc0",
            ),
            (
                "m/44'/283'/3'/0/0",
                "f035316f915b342ea5fe78dccb59d907b93805732219d436a1bd8488ff4e5b1b",
            ),
        ];

        for (path, expected_pubkey) in vectors {
            assert_eq!(
                derive_algo_pubkey(&seed, path),
                *expected_pubkey,
                "public key mismatch for path {}",
                path
            );
        }
    }

    #[test]
    fn test_algo_identity_keys() {
        let seed = algo_seed();
        // Identity context: m/44'/0'/account'/0/key_index (Peikert g=9)
        let vectors: &[(&str, &str)] = &[
            (
                "m/44'/0'/0'/0/0",
                "ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a",
            ),
            (
                "m/44'/0'/0'/0/1",
                "2b46c2af0890493e486049d456509a0199e565b41a5fb622f0ea4b9337bd2b97",
            ),
            (
                "m/44'/0'/0'/0/2",
                "2713f135f19ef3dcfca73cb536b1e077b1165cd0b7bedbef709447319ff0016d",
            ),
            (
                "m/44'/0'/1'/0/0",
                "232847ae1bb95babcaa50c8033fab98f59e4b4ad1d89ac523a90c830e4ceee4a",
            ),
            (
                "m/44'/0'/2'/0/1",
                "8f68b6572860d84e8a41e38db1c8c692ded5eb291846f2e5bbfde774a9c6d16e",
            ),
        ];

        for (path, expected_pubkey) in vectors {
            assert_eq!(
                derive_algo_pubkey(&seed, path),
                *expected_pubkey,
                "public key mismatch for path {}",
                path
            );
        }
    }

    #[test]
    fn test_algo_extended_private_keys() {
        let seed = algo_seed();
        // Verify full extended private keys [kL||kR||cc] for address context
        let vectors: &[(&str, &str)] = &[
            (
                "m/44'/283'/0'/0/0",
                "00cc7480c8edf9f64a680957e05cd0908f3b682a9ffdbafa2a61c43b6df67050\
              95a7d0d2f9afd1f472e855a0f6fe967ccb12f497cf3c8d3213c156e72c0de37a\
              27f9b4be231765ad6fb4a7d93bdf16e8d9ae87bf20662c8c21fb6acf1ce65325",
            ),
            (
                "m/44'/283'/0'/0/1",
                "b0cb47103426b932d562ff6f14e99ecc26b26aec080259e1190c869d6ac9c84f\
              ecff83895eb2f9ea75cad60044090cd8f386cff87715059a28a86765db2e3b13\
              4e90b59e711981eb6d9c0809c35da23726b997d5731c706309d9c8b3daa5f12c",
            ),
            (
                "m/44'/0'/0'/0/0",
                "70b91d1dbcf9cbb4486fddbececa0dcd2b898cfb0ce676fc1e18ce6fba169d4f\
              040706f4c965b6f0a72683332c64f4420c422c760fd8bc574a8886fd79edd8b9\
              8c3d61188964a420564560ef79219fc69df4279ecc71031df2fe53092feb9563",
            ),
        ];

        for (path, expected_ext) in vectors {
            let components: Vec<u32> = path[2..]
                .split('/')
                .map(|c| {
                    let hardened = c.ends_with('\'');
                    let idx: u32 = c.trim_end_matches('\'').parse().unwrap();
                    if hardened {
                        idx + 0x80000000
                    } else {
                        idx
                    }
                })
                .collect();

            let mut ext_key = hd::bip32_ed25519_from_seed(seed.expose()).unwrap();
            for idx in &components {
                ext_key = hd::bip32_ed25519_derive_child(&ext_key, *idx, 9).unwrap();
            }

            assert_eq!(
                hex::encode(&ext_key),
                *expected_ext,
                "extended key mismatch for path {}",
                path
            );
        }
    }

    #[test]
    fn test_algo_sign_verify_with_derived_key() {
        let seed = algo_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        let key = HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        let signer = signer_for_chain(ChainType::Avm);

        let message = b"test message";
        let result = signer.sign(key.expose(), message).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Verify signature
        let pubkey_bytes: [u8; 32] = result
            .public_key
            .as_ref()
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(message, &sig)
            .expect("signature should verify");

        // Public key should match the known test vector
        assert_eq!(
            hex::encode(pubkey_bytes),
            "7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9"
        );
    }
}
