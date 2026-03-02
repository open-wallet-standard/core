use crate::curve::Curve;
use crate::mnemonic::Mnemonic;
use crate::zeroizing::SecretBytes;
use hmac::{Hmac, Mac};
use sha2::Sha512;

/// Errors from HD key derivation.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    #[error("ed25519 requires hardened-only derivation")]
    Ed25519NonHardened,
}

/// HD key deriver supporting BIP-32 (secp256k1) and SLIP-10 (ed25519).
pub struct HdDeriver;

impl HdDeriver {
    /// Derive a child private key from a seed and derivation path.
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> {
        Self::validate_path(path)?;

        match curve {
            Curve::Secp256k1 => Self::derive_secp256k1(seed, path),
            Curve::Ed25519 => Self::derive_ed25519(seed, path),
        }
    }

    /// Convenience: derive from a mnemonic + passphrase + path + curve.
    pub fn derive_from_mnemonic(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        let seed = mnemonic.to_seed(passphrase);
        Self::derive(seed.expose(), path, curve)
    }

    /// Like `derive_from_mnemonic`, but checks the global key cache first.
    /// On cache miss, derives the key and inserts it into the cache.
    pub fn derive_from_mnemonic_cached(
        mnemonic: &Mnemonic,
        passphrase: &str,
        path: &str,
        curve: Curve,
    ) -> Result<SecretBytes, HdError> {
        use digest::Digest;

        // Build a cache key by hashing all inputs (avoids storing sensitive material in the key).
        let phrase = mnemonic.phrase();
        let mut hasher = sha2::Sha256::new();
        hasher.update(phrase.expose());
        hasher.update(b":");
        hasher.update(passphrase.as_bytes());
        hasher.update(b":");
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(match curve {
            Curve::Secp256k1 => b"secp256k1" as &[u8],
            Curve::Ed25519 => b"ed25519",
        });
        let cache_key = hex::encode(hasher.finalize());

        let cache = crate::global_key_cache();
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached);
        }

        let key = Self::derive_from_mnemonic(mnemonic, passphrase, path, curve)?;
        cache.insert(&cache_key, key.clone());
        Ok(key)
    }

    /// Validate a derivation path. Must start with "m/" and contain valid indices.
    pub fn validate_path(path: &str) -> Result<(), HdError> {
        if !path.starts_with("m/") && path != "m" {
            return Err(HdError::InvalidPath(format!(
                "path must start with 'm/', got '{}'",
                path
            )));
        }
        if path == "m" {
            return Ok(());
        }
        let components = path[2..].split('/');
        for component in components {
            let index_str = component.trim_end_matches('\'');
            if index_str.is_empty() {
                return Err(HdError::InvalidPath(format!(
                    "empty component in path '{}'",
                    path
                )));
            }
            index_str.parse::<u32>().map_err(|_| {
                HdError::InvalidPath(format!("invalid index '{}' in path '{}'", component, path))
            })?;
        }
        Ok(())
    }

    /// BIP-32 derivation for secp256k1 using coins-bip32.
    fn derive_secp256k1(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use coins_bip32::derived::DerivedXPriv;
        use coins_bip32::xkeys::Parent;
        use std::str::FromStr;

        let xpriv = DerivedXPriv::root_from_seed(seed, None)
            .map_err(|e| HdError::DerivationFailed(e.to_string()))?;

        let derivation_path = coins_bip32::path::DerivationPath::from_str(path)
            .map_err(|e| HdError::InvalidPath(e.to_string()))?;

        let derived = xpriv
            .derive_path(&derivation_path)
            .map_err(|e: coins_bip32::Bip32Error| HdError::DerivationFailed(e.to_string()))?;

        let signing_key: &k256::ecdsa::SigningKey = derived.as_ref();
        let key_bytes = signing_key.to_bytes();
        Ok(SecretBytes::new(key_bytes.to_vec()))
    }

    /// SLIP-10 derivation for ed25519 (hardened-only, HMAC-SHA512 chain).
    fn derive_ed25519(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        use zeroize::Zeroize;

        // Parse path components
        let components = if path == "m" {
            vec![]
        } else {
            path[2..]
                .split('/')
                .map(|c| {
                    if !c.ends_with('\'') {
                        return Err(HdError::Ed25519NonHardened);
                    }
                    let index_str = c.trim_end_matches('\'');
                    let index: u32 = index_str
                        .parse()
                        .map_err(|_| HdError::InvalidPath(format!("invalid index: {}", c)))?;
                    Ok(index)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        // SLIP-10: Master key generation
        type HmacSha512 = Hmac<Sha512>;
        let mut mac =
            HmacSha512::new_from_slice(b"ed25519 seed").expect("HMAC can take key of any size");
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let mut key = result[..32].to_vec();
        let mut chain_code = result[32..].to_vec();

        // Derive each component (hardened only)
        let mut data = Vec::new();
        for index in components {
            data.zeroize();
            data.clear();
            data.push(0u8); // 0x00 prefix for private key derivation
            data.extend_from_slice(&key);
            data.extend_from_slice(&(index + 0x80000000u32).to_be_bytes());

            let mut mac =
                HmacSha512::new_from_slice(&chain_code).expect("HMAC can take key of any size");
            mac.update(&data);
            let result = mac.finalize().into_bytes();

            key.zeroize();
            chain_code.zeroize();
            key = result[..32].to_vec();
            chain_code = result[32..].to_vec();
        }

        data.zeroize();
        chain_code.zeroize();
        Ok(SecretBytes::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_seed() -> SecretBytes {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        mnemonic.to_seed("")
    }

    #[test]
    fn test_derive_evm_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_solana_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0'", Curve::Ed25519).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_bitcoin_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/84'/0'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_cosmos_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/118'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_tron_account_0() {
        let seed = test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/195'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_convenience_matches_two_step() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = mnemonic.to_seed("");

        let key1 =
            HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_path_validation_valid() {
        assert!(HdDeriver::validate_path("m/44'/60'/0'/0/0").is_ok());
        assert!(HdDeriver::validate_path("m/44'/501'/0'/0'").is_ok());
        assert!(HdDeriver::validate_path("m").is_ok());
    }

    #[test]
    fn test_path_validation_invalid() {
        assert!(HdDeriver::validate_path("44'/60'/0'/0/0").is_err());
        assert!(HdDeriver::validate_path("").is_err());
        assert!(HdDeriver::validate_path("x/44'/60'").is_err());
    }

    #[test]
    fn test_slip10_rejects_non_hardened_ed25519() {
        let seed = test_seed();
        let result = HdDeriver::derive(seed.expose(), "m/44'/501'/0'/0", Curve::Ed25519);
        assert!(result.is_err());
        match result.unwrap_err() {
            HdError::Ed25519NonHardened => {}
            other => panic!("expected Ed25519NonHardened, got {:?}", other),
        }
    }

    #[test]
    fn test_deterministic() {
        let seed = test_seed();
        let key1 =
            HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 =
            HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = test_seed();
        let key0 =
            HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key1 =
            HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/1", Curve::Secp256k1).unwrap();
        assert_ne!(key0.expose(), key1.expose());
    }
}
