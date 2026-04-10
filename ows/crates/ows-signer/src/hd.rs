use crate::curve::Curve;
use crate::mnemonic::Mnemonic;
use crate::zeroizing::SecretBytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

/// Errors from HD key derivation.
#[derive(Debug, thiserror::Error)]
pub enum HdError {
    #[error("invalid derivation path: {0}")]
    InvalidPath(String),

    #[error("derivation failed: {0}")]
    DerivationFailed(String),

    #[error("ed25519 requires hardened-only derivation")]
    Ed25519NonHardened,

    #[error("invalid seed length: expected 16-64 bytes, got {0}")]
    InvalidSeedLength(usize),
}

/// HD key deriver supporting BIP-32 (secp256k1) and SLIP-10 (ed25519).
pub struct HdDeriver;

impl HdDeriver {
    /// Derive a child private key from a seed and derivation path.
    ///
    /// Seed must be 16-64 bytes (BIP-32 §2).
    pub fn derive(seed: &[u8], path: &str, curve: Curve) -> Result<SecretBytes, HdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(HdError::InvalidSeedLength(seed.len()));
        }
        Self::validate_path(path)?;

        match curve {
            Curve::Secp256k1 => Self::derive_secp256k1(seed, path),
            Curve::Ed25519 => Self::derive_ed25519(seed, path),
            Curve::Ed25519Bip32 => Self::derive_bip32_ed25519(seed, path),
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
            Curve::Ed25519Bip32 => b"ed25519-bip32",
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

    /// BIP32-Ed25519 derivation with Peikert's amendment.
    ///
    /// Reference: "BIP32-Ed25519: Hierarchical Deterministic Keys over a Non-linear Keyspace"
    /// Uses g=9 (Peikert mode) which zeros only 9 bits from each derived zL,
    /// allowing up to D=2^3=8 derivation levels (BIP-44 needs 5).
    ///
    /// Unlike SLIP-10, this supports both hardened and non-hardened child derivation.
    /// Returns the full 96-byte extended key [kL(32) || kR(32) || chainCode(32)].
    /// kL is the private scalar for Ed25519 signing.
    /// kR is the nonce source required for RFC 8032 EdDSA signing per the AF's
    /// xHD-Wallet-API reference implementation.
    fn derive_bip32_ed25519(seed: &[u8], path: &str) -> Result<SecretBytes, HdError> {
        // Peikert's g parameter: number of trailing bits to zero in zL
        const G: usize = 9;

        // A) Root key generation from seed
        let root = bip32_ed25519_from_seed(seed)?;

        // Parse path components
        let components = if path == "m" {
            vec![]
        } else {
            path[2..]
                .split('/')
                .map(|c| {
                    let hardened = c.ends_with('\'');
                    let index_str = c.trim_end_matches('\'');
                    let index: u32 = index_str
                        .parse()
                        .map_err(|_| HdError::InvalidPath(format!("invalid index: {}", c)))?;
                    if hardened {
                        Ok(index + 0x80000000)
                    } else {
                        Ok(index)
                    }
                })
                .collect::<Result<Vec<_>, HdError>>()?
        };

        // Derive each child node
        let mut extended_key = root; // 96 bytes: [kL(32) | kR(32) | chainCode(32)]
        for index in components {
            extended_key = bip32_ed25519_derive_child(&extended_key, index, G)?;
        }

        // Return the full 96-byte extended key [kL || kR || chainCode]
        // kR is needed by AvmSigner for RFC 8032 EdDSA signing (nonce source),
        // matching the AF's rawSign() which uses kR directly.
        Ok(SecretBytes::new(extended_key))
    }
}

// =============================================================================
// BIP32-Ed25519 helper functions (Peikert's amendment)
// =============================================================================

/// Generate the root extended key (kL, kR, c) from a BIP-39 seed.
///
/// Reference: Section V.A "Root keys" of the BIP32-Ed25519 paper.
pub fn bip32_ed25519_from_seed(seed: &[u8]) -> Result<Vec<u8>, HdError> {
    type HmacSha512 = Hmac<Sha512>;

    // k = H512(seed)
    let mut k = Sha512::digest(seed).to_vec();
    let mut kl = k[..32].to_vec();
    let mut kr = k[32..64].to_vec();

    // While the third highest bit of the last byte of kL is not zero
    while (kl[31] & 0b0010_0000) != 0 {
        let mut mac = HmacSha512::new_from_slice(&kl).expect("HMAC can take key of any size");
        mac.update(&kr);
        k = mac.finalize().into_bytes().to_vec();
        kl = k[..32].to_vec();
        kr = k[32..64].to_vec();
    }

    // Clamp kL:
    kl[0] &= 0b1111_1000; // clear lowest 3 bits
    kl[31] &= 0b0111_1111; // clear highest bit
    kl[31] |= 0b0100_0000; // set second highest bit

    // Chain code: SHA-256(0x01 || seed)
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(seed);
    let chain_code = hasher.finalize().to_vec();

    // Return 96 bytes: kL(32) || kR(32) || chainCode(32)
    let mut result = Vec::with_capacity(96);
    result.extend_from_slice(&kl);
    result.extend_from_slice(&kr);
    result.extend_from_slice(&chain_code);
    Ok(result)
}

/// Truncate an array by zeroing the last `g` trailing bits (big-endian bit order,
/// little-endian byte order — i.e. the highest bits of the last bytes).
pub fn trunc_256_minus_g_bits(array: &[u8], g: usize) -> Vec<u8> {
    let mut truncated = array.to_vec();
    let mut remaining = g;

    // Start from the last byte and move backward
    for i in (0..truncated.len()).rev() {
        if remaining == 0 {
            break;
        }
        if remaining >= 8 {
            truncated[i] = 0;
            remaining -= 8;
        } else {
            truncated[i] &= 0xFF >> remaining;
            break;
        }
    }
    truncated
}

/// Scalar multiplication with the Ed25519 base point (no clamping).
/// Returns the 32-byte compressed point.
pub fn ed25519_scalar_mult_base_noclamp(scalar: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;

    // Convert little-endian bytes to scalar.
    // Clear the top bit to ensure it fits in the field, matching
    // the noclamp behavior from the TypeScript reference.
    let mut scalar_bytes = *scalar;
    scalar_bytes[31] &= 0x7F; // clear bit 255
    let s = Scalar::from_bytes_mod_order(scalar_bytes);
    let point = ED25519_BASEPOINT_TABLE * &s;
    point.compress().to_bytes()
}

/// Derive a child node from an extended key using BIP32-Ed25519.
///
/// Reference: Section V.B "Child Keys" and V.C "Private Child Key Derivation".
///
/// `extended_key`: 96 bytes [kL(32) | kR(32) | chainCode(32)]
/// `index`: child index (>= 0x80000000 for hardened)
/// `g`: Peikert parameter — number of trailing bits to zero in zL
pub fn bip32_ed25519_derive_child(
    extended_key: &[u8],
    index: u32,
    g: usize,
) -> Result<Vec<u8>, HdError> {
    type HmacSha512 = Hmac<Sha512>;

    let kl = &extended_key[0..32];
    let kr = &extended_key[32..64];
    let cc = &extended_key[64..96];

    let (z, child_chain_code) = if index < 0x80000000 {
        // Non-hardened derivation
        let pk = ed25519_scalar_mult_base_noclamp(kl.try_into().unwrap());

        let mut data = Vec::with_capacity(1 + 32 + 4);
        data.push(0x02);
        data.extend_from_slice(&pk);
        data.extend_from_slice(&index.to_le_bytes());

        let z = {
            let mut mac = HmacSha512::new_from_slice(cc).expect("HMAC can take key of any size");
            mac.update(&data);
            mac.finalize().into_bytes().to_vec()
        };

        data[0] = 0x03;
        let full_cc = {
            let mut mac = HmacSha512::new_from_slice(cc).expect("HMAC can take key of any size");
            mac.update(&data);
            mac.finalize().into_bytes().to_vec()
        };
        let child_cc = full_cc[32..64].to_vec();

        (z, child_cc)
    } else {
        // Hardened derivation
        let mut data = Vec::with_capacity(1 + 64 + 4);
        data.push(0x00);
        data.extend_from_slice(kl);
        data.extend_from_slice(kr);
        data.extend_from_slice(&index.to_le_bytes());

        let z = {
            let mut mac = HmacSha512::new_from_slice(cc).expect("HMAC can take key of any size");
            mac.update(&data);
            mac.finalize().into_bytes().to_vec()
        };

        data[0] = 0x01;
        let full_cc = {
            let mut mac = HmacSha512::new_from_slice(cc).expect("HMAC can take key of any size");
            mac.update(&data);
            mac.finalize().into_bytes().to_vec()
        };
        let child_cc = full_cc[32..64].to_vec();

        (z, child_cc)
    };

    // Compute child private key using Peikert's amendment:
    // zL = trunc_256_minus_g_bits(z[0..32], g)
    // childKL = kL + 8 * zL  (as little-endian 256-bit integers)
    // childKR = kR + z[32..64]  (as little-endian 256-bit integers, truncated to 32 bytes)
    let z_left = trunc_256_minus_g_bits(&z[0..32], g);
    let z_right = &z[32..64];

    // kL + 8 * zL using 512-bit arithmetic to avoid overflow
    let child_kl = {
        let mut result = [0u8; 64]; // 512-bit accumulator

        // Load kL into accumulator (little-endian)
        result[..32].copy_from_slice(kl);

        // Add 8 * zL
        let mut carry: u16 = 0;
        for i in 0..32 {
            let zl_times_8 = (z_left[i] as u16) << 3
                | if i > 0 {
                    (z_left[i - 1] as u16) >> 5
                } else {
                    0
                };
            let sum = result[i] as u16 + (zl_times_8 & 0xFF) + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        // Handle the final bits of the shift for byte index 32
        let final_shift = (z_left[31] as u16) >> 5;
        let sum = result[32] as u16 + final_shift + carry;
        result[32] = sum as u8;
        // Propagate any remaining carry
        let mut c = sum >> 8;
        for byte in &mut result[33..64] {
            if c == 0 {
                break;
            }
            let s = *byte as u16 + c;
            *byte = s as u8;
            c = s >> 8;
        }

        // Safety check: result should fit in 256 bits for valid keys
        let mut fits = true;
        for b in &result[32..] {
            if *b != 0 {
                fits = false;
                break;
            }
        }
        if !fits {
            return Err(HdError::DerivationFailed(
                "child key overflow: kL + 8*zL exceeds 2^256".into(),
            ));
        }

        result[..32].to_vec()
    };

    // childKR = (kR + zRight) mod 2^256, keep lower 32 bytes
    let child_kr = {
        let mut result = [0u8; 32];
        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = kr[i] as u16 + z_right[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }
        result.to_vec()
    };

    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(&child_kl);
    out.extend_from_slice(&child_kr);
    out.extend_from_slice(&child_chain_code);
    Ok(out)
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
        let key = HdDeriver::derive(seed.expose(), "m/44'/118'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_tron_account_0() {
        let seed = test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/195'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_convenience_matches_two_step() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let seed = mnemonic.to_seed("");

        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
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

    // === BIP-32 spec test vectors (secp256k1) ===
    // Source: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors

    #[test]
    fn test_bip32_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            (
                "m/0'",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            ),
            (
                "m/0'/1",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            ),
            (
                "m/0'/1/2'",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            ),
            (
                "m/0'/1/2'/2",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            ),
            (
                "m/0'/1/2'/2/1000000000",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_bip32_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            (
                "m/0",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
            ),
            (
                "m/0/2147483647'",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
            ),
            (
                "m/0/2147483647'/1",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
            ),
            (
                "m/0/2147483647'/1/2147483646'",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
            ),
            (
                "m/0/2147483647'/1/2147483646'/2",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Secp256k1)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "BIP-32 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === SLIP-10 spec test vectors (ed25519) ===
    // Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vectors

    #[test]
    fn test_slip10_vector1_chain() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

        let cases = [
            (
                "m/0'",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            ),
            (
                "m/0'/1'",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
            ),
            (
                "m/0'/1'/2'",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            ),
            (
                "m/0'/1'/2'/2'",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
            ),
            (
                "m/0'/1'/2'/2'/1000000000'",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 1 mismatch at {}",
                path
            );
        }
    }

    #[test]
    fn test_slip10_vector2_chain() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .unwrap();

        let cases = [
            (
                "m/0'",
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
            ),
            (
                "m/0'/2147483647'",
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
            ),
            (
                "m/0'/2147483647'/1'",
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'",
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
            ),
            (
                "m/0'/2147483647'/1'/2147483646'/2'",
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
            ),
        ];

        for (path, expected_hex) in cases {
            let key = HdDeriver::derive(&seed, path, Curve::Ed25519)
                .unwrap_or_else(|e| panic!("failed to derive {}: {}", path, e));
            assert_eq!(
                hex::encode(key.expose()),
                expected_hex,
                "SLIP-10 vector 2 mismatch at {}",
                path
            );
        }
    }

    // === Seed length validation ===

    #[test]
    fn test_seed_length_too_short() {
        let seed = [0u8; 15];
        let result = HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(15))));
    }

    #[test]
    fn test_seed_length_too_long() {
        let seed = [0u8; 65];
        let result = HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1);
        assert!(matches!(result, Err(HdError::InvalidSeedLength(65))));
    }

    #[test]
    fn test_seed_length_minimum_accepted() {
        let seed = [0u8; 16];
        assert!(HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    #[test]
    fn test_seed_length_maximum_accepted() {
        let seed = [0u8; 64];
        assert!(HdDeriver::derive(&seed, "m/0'", Curve::Secp256k1).is_ok());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn test_abandon_mnemonic_evm_address() {
        // Known test vector: "abandon" mnemonic → known EVM address
        // This address is well-documented across the ecosystem
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();

        // Derive the EVM address from the key
        let signer = crate::chains::EvmSigner;
        use crate::traits::ChainSigner;
        let address = signer.derive_address(key.expose()).unwrap();
        assert_eq!(
            address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
            "abandon mnemonic should derive to known EVM address"
        );
    }

    #[test]
    fn test_same_mnemonic_same_path_same_curve_same_key() {
        // Multiple independent derivations must produce identical results
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let key1 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key2 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let key3 = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();

        assert_eq!(key1.expose(), key2.expose());
        assert_eq!(key2.expose(), key3.expose());
    }

    #[test]
    fn test_different_index_different_key_evm() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/1", Curve::Secp256k1)
                .unwrap();
        let key2 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/2", Curve::Secp256k1)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
        assert_ne!(key1.expose(), key2.expose());
        assert_ne!(key0.expose(), key2.expose());
    }

    #[test]
    fn test_different_index_different_key_ed25519() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let key0 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        let key1 =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/1'/0'", Curve::Ed25519)
                .unwrap();

        assert_ne!(key0.expose(), key1.expose());
    }

    #[test]
    fn test_cached_derivation_matches_uncached() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let path = "m/44'/60'/0'/0/0";
        let curve = Curve::Secp256k1;

        let uncached = HdDeriver::derive_from_mnemonic(&mnemonic, "", path, curve).unwrap();
        let cached = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", path, curve).unwrap();

        assert_eq!(uncached.expose(), cached.expose());
    }

    #[test]
    fn test_key_length_32_bytes_all_curves() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();

        let secp_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/60'/0'/0/0", Curve::Secp256k1)
                .unwrap();
        assert_eq!(secp_key.len(), 32);

        let ed_key =
            HdDeriver::derive_from_mnemonic(&mnemonic, "", "m/44'/501'/0'/0'", Curve::Ed25519)
                .unwrap();
        assert_eq!(ed_key.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let seed = test_seed();
        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key2 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = test_seed();
        let key0 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/0", Curve::Secp256k1).unwrap();
        let key1 = HdDeriver::derive(seed.expose(), "m/44'/60'/0'/0/1", Curve::Secp256k1).unwrap();
        assert_ne!(key0.expose(), key1.expose());
    }

    // === BIP32-Ed25519 tests ===

    const ALGORAND_MNEMONIC: &str = "salon zoo engage submit smile frost later decide wing sight chaos renew lizard rely canal coral scene hobby scare step bus leaf tobacco slice";

    fn algorand_test_seed() -> SecretBytes {
        let mnemonic = Mnemonic::from_phrase(ALGORAND_MNEMONIC).unwrap();
        mnemonic.to_seed("")
    }

    #[test]
    fn test_bip32_ed25519_root_key() {
        let seed = algorand_test_seed();
        let root = bip32_ed25519_from_seed(seed.expose()).unwrap();
        assert_eq!(root.len(), 96);
        let expected = hex::decode(
            "a8ba80028922d9fcfa055c78aede55b5c575bcd8d5a53168edf45f36d9ec8f46\
             94592b4bc892907583e22669ecdf1b0409a9f3bd5549f2dd751b51360909cd05\
             796b9206ec30e142e94b790a98805bf999042b55046963174ee6cee2d0375946",
        )
        .unwrap();
        assert_eq!(root, expected);
    }

    #[test]
    fn test_bip32_ed25519_derive_algorand_address_0_0() {
        // m'/44'/283'/0'/0/0 with Peikert (g=9) — public key
        let seed = algorand_test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        // key is the full extended key [kL(32) || kR(32) || cc(32)]; extract kL for pubkey
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        let pubkey = ed25519_scalar_mult_base_noclamp(&scalar);
        let expected =
            hex::decode("7bda7ac12627b2c259f1df6875d30c10b35f55b33ad2cc8ea2736eaa3ebcfab9")
                .unwrap();
        assert_eq!(pubkey.to_vec(), expected);
    }

    #[test]
    fn test_bip32_ed25519_derive_algorand_address_0_1() {
        // m'/44'/283'/0'/0/1 with Peikert (g=9)
        let seed = algorand_test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/1", Curve::Ed25519Bip32).unwrap();
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        let pubkey = ed25519_scalar_mult_base_noclamp(&scalar);
        let expected =
            hex::decode("5bae8828f111064637ac5061bd63bc4fcfe4a833252305f25eeab9c64ecdf519")
                .unwrap();
        assert_eq!(pubkey.to_vec(), expected);
    }

    #[test]
    fn test_bip32_ed25519_derive_algorand_address_0_2() {
        // m'/44'/283'/0'/0/2 with Peikert (g=9)
        let seed = algorand_test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/2", Curve::Ed25519Bip32).unwrap();
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        let pubkey = ed25519_scalar_mult_base_noclamp(&scalar);
        let expected =
            hex::decode("00a72635e97cba966529e9bfb4baf4a32d7b8cd2fcd8e2476ce5be1177848cb3")
                .unwrap();
        assert_eq!(pubkey.to_vec(), expected);
    }

    #[test]
    fn test_bip32_ed25519_derive_hard_account_1() {
        // m'/44'/283'/1'/0/0 with Peikert (g=9)
        let seed = algorand_test_seed();
        let key =
            HdDeriver::derive(seed.expose(), "m/44'/283'/1'/0/0", Curve::Ed25519Bip32).unwrap();
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        let pubkey = ed25519_scalar_mult_base_noclamp(&scalar);
        let expected =
            hex::decode("358d8c4382992849a764438e02b1c45c2ca4e86bbcfe10fd5b963f3610012bc9")
                .unwrap();
        assert_eq!(pubkey.to_vec(), expected);
    }

    #[test]
    fn test_bip32_ed25519_derive_identity_0_0() {
        // m'/44'/0'/0'/0/0 with Peikert (g=9) — identity key context
        let seed = algorand_test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/0'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        let scalar: [u8; 32] = key.expose()[..32].try_into().unwrap();
        let pubkey = ed25519_scalar_mult_base_noclamp(&scalar);
        let expected =
            hex::decode("ff8b1863ef5e40d0a48c245f26a6dbdf5da94dc75a1851f51d8a04e547bd5f5a")
                .unwrap();
        assert_eq!(pubkey.to_vec(), expected);
    }

    #[test]
    fn test_bip32_ed25519_allows_non_hardened() {
        // BIP32-Ed25519 allows non-hardened derivation (unlike SLIP-10)
        let seed = algorand_test_seed();
        let key = HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32);
        assert!(key.is_ok());
    }

    #[test]
    fn test_bip32_ed25519_deterministic() {
        let seed = algorand_test_seed();
        let key1 =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        let key2 =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_bip32_ed25519_different_indices() {
        let seed = algorand_test_seed();
        let key0 =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/0", Curve::Ed25519Bip32).unwrap();
        let key1 =
            HdDeriver::derive(seed.expose(), "m/44'/283'/0'/0/1", Curve::Ed25519Bip32).unwrap();
        assert_ne!(key0.expose(), key1.expose());
    }
}
