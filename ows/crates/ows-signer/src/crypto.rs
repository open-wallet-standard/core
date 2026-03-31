use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::zeroizing::SecretBytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub auth_tag: String,
    pub kdf: String,
    pub kdfparams: KdfParamsVariant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

/// Scrypt KDF parameters (existing format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: String,
}

/// HKDF-SHA256 KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HkdfKdfParams {
    pub dklen: u32,
    pub salt: String,
    pub info: String,
}

/// Unified KDF parameters — deserializes to whichever variant matches the fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParamsVariant {
    Scrypt(KdfParams),
    Hkdf(HkdfKdfParams),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

// Prevent fast-kdf from being used in release builds — weak KDF is test-only.
#[cfg(all(feature = "fast-kdf", not(debug_assertions)))]
compile_error!(
    "The `fast-kdf` feature reduces scrypt to 2^10 iterations and must not be used in release builds. \
     Use dev-dependencies to enable it for tests only."
);

// Production: log_n=16 (~5s per call, down from ~20s at log_n=18)
// Tests: log_n=10 (<10ms per call)
#[cfg(any(test, feature = "fast-kdf"))]
const KDF_LOG_N: u8 = 10;
#[cfg(not(any(test, feature = "fast-kdf")))]
const KDF_LOG_N: u8 = 16;

const KDF_N: u32 = 1 << (KDF_LOG_N as u32);
const KDF_R: u32 = 8;
const KDF_P: u32 = 1;
const KDF_DKLEN: u32 = 32;

/// Encrypt plaintext bytes using a passphrase (scrypt KDF + AES-256-GCM).
/// Returns a CryptoEnvelope suitable for JSON serialization.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<CryptoEnvelope, CryptoError> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    let params = ScryptParams::new(KDF_LOG_N, KDF_R, KDF_P, KDF_DKLEN as usize)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let mut derived_key = [0u8; 32];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // AES-GCM appends a 16-byte auth tag to the ciphertext
    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_offset];
    let auth_tag = &ciphertext_with_tag[tag_offset..];

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_string(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: hex::encode(ciphertext),
        auth_tag: hex::encode(auth_tag),
        kdf: "scrypt".to_string(),
        kdfparams: KdfParamsVariant::Scrypt(KdfParams {
            dklen: KDF_DKLEN,
            n: KDF_N,
            r: KDF_R,
            p: KDF_P,
            salt: hex::encode(salt),
        }),
    })
}

/// Decrypt a CryptoEnvelope using a passphrase (scrypt) or token (HKDF).
/// Dispatches on the `kdf` field: `"scrypt"` or `"hkdf-sha256"`.
/// Returns the decrypted plaintext as SecretBytes (zeroized on drop).
pub fn decrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, CryptoError> {
    match envelope.kdf.as_str() {
        "scrypt" => decrypt_scrypt(envelope, passphrase),
        "hkdf-sha256" => decrypt_hkdf(envelope, passphrase),
        other => Err(CryptoError::InvalidParams(format!(
            "unsupported KDF: {other}"
        ))),
    }
}

/// Decrypt using scrypt KDF (existing passphrase path).
fn decrypt_scrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, CryptoError> {
    let kdfparams = match &envelope.kdfparams {
        KdfParamsVariant::Scrypt(p) => p,
        _ => {
            return Err(CryptoError::InvalidParams(
                "expected scrypt kdfparams for kdf=scrypt".into(),
            ))
        }
    };

    let salt =
        hex::decode(&kdfparams.salt).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let iv = hex::decode(&envelope.cipherparams.iv)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let auth_tag =
        hex::decode(&envelope.auth_tag).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    // Validate KDF parameters to prevent downgrade attacks.
    let n = kdfparams.n;
    if n == 0 || (n & (n - 1)) != 0 {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt N must be a power of 2, got {n}"
        )));
    }
    if n < KDF_N {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt N={n} is below minimum {KDF_N} — possible downgrade attack"
        )));
    }
    if kdfparams.r < KDF_R {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt r={} is below minimum {KDF_R} — possible downgrade attack",
            kdfparams.r
        )));
    }
    if kdfparams.p < KDF_P {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt p={} is below minimum {KDF_P} — possible downgrade attack",
            kdfparams.p
        )));
    }
    if kdfparams.dklen < KDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "dklen={} is below minimum {KDF_DKLEN}",
            kdfparams.dklen
        )));
    }
    if kdfparams.dklen != KDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "dklen={} is unsupported, expected exactly {KDF_DKLEN}",
            kdfparams.dklen
        )));
    }

    let log_n = n.trailing_zeros() as u8;
    let params = ScryptParams::new(log_n, kdfparams.r, kdfparams.p, kdfparams.dklen as usize)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    let mut derived_key = vec![0u8; kdfparams.dklen as usize];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(SecretBytes::new(plaintext))
}

const HKDF_INFO: &[u8] = b"ows-api-key-v1";
const HKDF_DKLEN: u32 = 32;

/// Encrypt plaintext using an API token as the key material (HKDF-SHA256 + AES-256-GCM).
/// The token is high-entropy (256-bit random), so HKDF is appropriate — no expensive KDF needed.
pub fn encrypt_with_hkdf(plaintext: &[u8], token: &str) -> Result<CryptoEnvelope, CryptoError> {
    let mut rng = rand::thread_rng();

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut derived_key)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);
    let ciphertext_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let tag_offset = ciphertext_with_tag.len() - 16;
    let ciphertext = &ciphertext_with_tag[..tag_offset];
    let auth_tag = &ciphertext_with_tag[tag_offset..];

    Ok(CryptoEnvelope {
        cipher: "aes-256-gcm".to_string(),
        cipherparams: CipherParams {
            iv: hex::encode(iv),
        },
        ciphertext: hex::encode(ciphertext),
        auth_tag: hex::encode(auth_tag),
        kdf: "hkdf-sha256".to_string(),
        kdfparams: KdfParamsVariant::Hkdf(HkdfKdfParams {
            dklen: HKDF_DKLEN,
            salt: hex::encode(salt),
            info: String::from_utf8_lossy(HKDF_INFO).into_owned(),
        }),
    })
}

/// Decrypt a CryptoEnvelope that was encrypted with HKDF (API token path).
fn decrypt_hkdf(envelope: &CryptoEnvelope, token: &str) -> Result<SecretBytes, CryptoError> {
    let kdfparams = match &envelope.kdfparams {
        KdfParamsVariant::Hkdf(p) => p,
        _ => {
            return Err(CryptoError::InvalidParams(
                "expected HKDF kdfparams for kdf=hkdf-sha256".into(),
            ))
        }
    };

    if kdfparams.dklen != HKDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "HKDF dklen={} is unsupported, expected exactly {HKDF_DKLEN}",
            kdfparams.dklen
        )));
    }

    let salt =
        hex::decode(&kdfparams.salt).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let iv = hex::decode(&envelope.cipherparams.iv)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let auth_tag =
        hex::decode(&envelope.auth_tag).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(&salt), token.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(kdfparams.info.as_bytes(), &mut derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);

    let mut combined = ciphertext;
    combined.extend_from_slice(&auth_tag);

    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    Ok(SecretBytes::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extract mutable scrypt params from an envelope (for test tampering).
    fn scrypt_params_mut(envelope: &mut CryptoEnvelope) -> &mut KdfParams {
        match &mut envelope.kdfparams {
            KdfParamsVariant::Scrypt(p) => p,
            _ => panic!("expected scrypt params"),
        }
    }

    /// Extract scrypt params from an envelope (for assertions).
    fn scrypt_params(envelope: &CryptoEnvelope) -> &KdfParams {
        match &envelope.kdfparams {
            KdfParamsVariant::Scrypt(p) => p,
            _ => panic!("expected scrypt params"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello world";
        let passphrase = "my-secret-passphrase";

        let envelope = encrypt(plaintext, passphrase).unwrap();
        let decrypted = decrypt(&envelope, passphrase).unwrap();

        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let plaintext = b"hello world";
        let envelope = encrypt(plaintext, "pass1").unwrap();
        let result = decrypt(&envelope, "pass2");

        assert!(result.is_err());
    }

    #[test]
    fn test_different_encryptions_different_ciphertext() {
        let plaintext = b"same data";
        let passphrase = "same-pass";

        let env1 = encrypt(plaintext, passphrase).unwrap();
        let env2 = encrypt(plaintext, passphrase).unwrap();

        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(scrypt_params(&env1).salt, scrypt_params(&env2).salt);
        assert_ne!(env1.cipherparams.iv, env2.cipherparams.iv);
    }

    #[test]
    fn test_envelope_serde_roundtrip() {
        let plaintext = b"serde test";
        let envelope = encrypt(plaintext, "pass").unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: CryptoEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.cipher, envelope.cipher);
        assert_eq!(deserialized.ciphertext, envelope.ciphertext);
        assert_eq!(deserialized.auth_tag, envelope.auth_tag);
        assert_eq!(
            scrypt_params(&deserialized).salt,
            scrypt_params(&envelope).salt
        );
        assert_eq!(deserialized.cipherparams.iv, envelope.cipherparams.iv);

        let decrypted = decrypt(&deserialized, "pass").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        let plaintext = vec![0xAB; 1024];
        let passphrase = "test-passphrase-for-zeroize";

        let envelope = encrypt(&plaintext, passphrase).unwrap();
        let decrypted = decrypt(&envelope, passphrase).unwrap();

        assert_eq!(decrypted.expose(), &plaintext[..]);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_still_fails() {
        let plaintext = b"sensitive data";
        let envelope = encrypt(plaintext, "correct").unwrap();
        let result = decrypt(&envelope, "wrong");
        assert!(result.is_err());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn test_encrypt_decrypt_empty_passphrase() {
        let plaintext = b"data with empty passphrase";
        let envelope = encrypt(plaintext, "").unwrap();
        let decrypted = decrypt(&envelope, "").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_decrypt_empty_passphrase_rejects_nonempty() {
        let plaintext = b"data with empty passphrase";
        let envelope = encrypt(plaintext, "").unwrap();
        let result = decrypt(&envelope, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_malformed_iv_bad_hex() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        envelope.cipherparams.iv = "not-valid-hex!!!".to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_salt_bad_hex() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        scrypt_params_mut(&mut envelope).salt = "zz".to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_ciphertext_bad_hex() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        envelope.ciphertext = "not-hex".to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_malformed_auth_tag_bad_hex() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        envelope.auth_tag = "not-hex".to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_truncated_auth_tag() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        envelope.auth_tag = envelope.auth_tag[..8].to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_ciphertext() {
        let mut envelope = encrypt(b"test data here", "pass").unwrap();
        envelope.ciphertext = envelope.ciphertext[..4].to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_n_not_power_of_2() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        scrypt_params_mut(&mut envelope).n = 3;
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_n_zero() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        scrypt_params_mut(&mut envelope).n = 0;
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_n_below_minimum() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        scrypt_params_mut(&mut envelope).n = 512; // 2^9, below test minimum of 2^10
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_decrypt_dklen_below_32() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        scrypt_params_mut(&mut envelope).dklen = 16;
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_envelope_fields_correct() {
        let envelope = encrypt(b"test", "pass").unwrap();
        let kp = scrypt_params(&envelope);
        assert_eq!(envelope.cipher, "aes-256-gcm");
        assert_eq!(envelope.kdf, "scrypt");
        assert_eq!(kp.dklen, 32);
        assert_eq!(kp.r, KDF_R);
        assert_eq!(kp.p, KDF_P);
        assert_eq!(envelope.cipherparams.iv.len(), 24);
        assert_eq!(kp.salt.len(), 64);
        assert_eq!(envelope.auth_tag.len(), 32);
    }

    #[test]
    fn test_decrypt_dklen_above_32_should_not_panic() {
        let plaintext = b"test data";
        let mut envelope = encrypt(plaintext, "pass").unwrap();
        scrypt_params_mut(&mut envelope).dklen = 48;

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| decrypt(&envelope, "pass")));

        match result {
            Ok(Err(_)) => { /* Good: returned a proper error */ }
            Ok(Ok(_)) => {
                panic!("decrypt with dklen=48 should not succeed")
            }
            Err(_) => {
                panic!(
                    "decrypt with dklen=48 panicked instead of returning an error — \
                     Key::<Aes256Gcm>::from_slice() requires exactly 32 bytes"
                )
            }
        }
    }

    // === HKDF tests ===

    #[test]
    fn test_hkdf_encrypt_decrypt_roundtrip() {
        let plaintext = b"hello from HKDF";
        let token = "ows_key_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6";

        let envelope = encrypt_with_hkdf(plaintext, token).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");

        let decrypted = decrypt(&envelope, token).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_hkdf_wrong_token_fails() {
        let plaintext = b"secret data";
        let envelope = encrypt_with_hkdf(plaintext, "token1").unwrap();
        let result = decrypt(&envelope, "token2");
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_different_encryptions_different_ciphertext() {
        let plaintext = b"same data";
        let token = "same-token";

        let env1 = encrypt_with_hkdf(plaintext, token).unwrap();
        let env2 = encrypt_with_hkdf(plaintext, token).unwrap();

        assert_ne!(env1.ciphertext, env2.ciphertext);
        assert_ne!(env1.cipherparams.iv, env2.cipherparams.iv);
    }

    #[test]
    fn test_hkdf_envelope_fields_correct() {
        let envelope = encrypt_with_hkdf(b"test", "token").unwrap();
        assert_eq!(envelope.cipher, "aes-256-gcm");
        assert_eq!(envelope.kdf, "hkdf-sha256");
        assert_eq!(envelope.cipherparams.iv.len(), 24); // 12 bytes
        assert_eq!(envelope.auth_tag.len(), 32); // 16 bytes

        let kp = match &envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => p,
            _ => panic!("expected HKDF params"),
        };
        assert_eq!(kp.dklen, 32);
        assert_eq!(kp.salt.len(), 64); // 32 bytes
        assert_eq!(kp.info, "ows-api-key-v1");
    }

    #[test]
    fn test_hkdf_serde_roundtrip() {
        let plaintext = b"serde hkdf test";
        let token = "ows_key_test_token";
        let envelope = encrypt_with_hkdf(plaintext, token).unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: CryptoEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.kdf, "hkdf-sha256");
        let decrypted = decrypt(&deserialized, token).unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_hkdf_large_payload() {
        let plaintext = vec![0xCD; 2048];
        let token = "ows_key_large_payload_test";

        let envelope = encrypt_with_hkdf(&plaintext, token).unwrap();
        let decrypted = decrypt(&envelope, token).unwrap();
        assert_eq!(decrypted.expose(), &plaintext[..]);
    }

    #[test]
    fn test_decrypt_unsupported_kdf_rejected() {
        let mut envelope = encrypt(b"test", "pass").unwrap();
        envelope.kdf = "argon2id".to_string();
        let result = decrypt(&envelope, "pass");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_scrypt_and_hkdf_envelopes_not_interchangeable() {
        let plaintext = b"test data";
        let credential = "shared-credential";

        let scrypt_env = encrypt(plaintext, credential).unwrap();
        let hkdf_env = encrypt_with_hkdf(plaintext, credential).unwrap();

        // Scrypt envelope decrypted with scrypt KDF should work
        assert!(decrypt(&scrypt_env, credential).is_ok());
        // HKDF envelope decrypted with HKDF KDF should work
        assert!(decrypt(&hkdf_env, credential).is_ok());

        // Cross-KDF: manually change the kdf field to mismatch params
        let mut tampered = scrypt_env.clone();
        tampered.kdf = "hkdf-sha256".to_string();
        assert!(decrypt(&tampered, credential).is_err());
    }

    #[test]
    fn test_hkdf_decrypt_tampered_dklen() {
        let plaintext = b"test";
        let token = "test-token";
        let mut envelope = encrypt_with_hkdf(plaintext, token).unwrap();

        match &mut envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => p.dklen = 64,
            _ => panic!("expected HKDF params"),
        }

        let result = decrypt(&envelope, token);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidParams(_)));
    }

    #[test]
    fn test_existing_scrypt_json_backward_compat() {
        // Ensure a JSON envelope with scrypt kdfparams (the only format before this change)
        // still deserializes correctly.
        let json = r#"{
            "cipher": "aes-256-gcm",
            "cipherparams": { "iv": "aabbccddeeff00112233aabb" },
            "ciphertext": "deadbeef",
            "auth_tag": "00112233445566778899aabbccddeeff",
            "kdf": "scrypt",
            "kdfparams": { "dklen": 32, "n": 1024, "r": 8, "p": 1, "salt": "0011223344556677889900112233445566778899001122334455667788990011" }
        }"#;

        let envelope: CryptoEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.kdf, "scrypt");
        let kp = scrypt_params(&envelope);
        assert_eq!(kp.n, 1024);
        assert_eq!(kp.r, 8);
        assert_eq!(kp.dklen, 32);
    }

    #[test]
    fn test_hkdf_json_deserialize() {
        let json = r#"{
            "cipher": "aes-256-gcm",
            "cipherparams": { "iv": "aabbccddeeff00112233aabb" },
            "ciphertext": "deadbeef",
            "auth_tag": "00112233445566778899aabbccddeeff",
            "kdf": "hkdf-sha256",
            "kdfparams": { "dklen": 32, "salt": "0011223344556677889900112233445566778899001122334455667788990011", "info": "ows-api-key-v1" }
        }"#;

        let envelope: CryptoEnvelope = serde_json::from_str(json).unwrap();
        assert_eq!(envelope.kdf, "hkdf-sha256");
        match &envelope.kdfparams {
            KdfParamsVariant::Hkdf(p) => {
                assert_eq!(p.dklen, 32);
                assert_eq!(p.info, "ows-api-key-v1");
            }
            _ => panic!("expected HKDF params"),
        }
    }
}
