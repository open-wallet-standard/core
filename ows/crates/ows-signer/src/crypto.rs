use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::RngCore;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::zeroizing::SecretBytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoEnvelope {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub auth_tag: String,
    pub kdf: String,
    pub kdfparams: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub dklen: u32,
    pub n: u32,
    pub r: u32,
    pub p: u32,
    pub salt: String,
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
        kdfparams: KdfParams {
            dklen: KDF_DKLEN,
            n: KDF_N,
            r: KDF_R,
            p: KDF_P,
            salt: hex::encode(salt),
        },
    })
}

/// Decrypt a CryptoEnvelope using a passphrase.
/// Returns the decrypted plaintext as SecretBytes (zeroized on drop).
pub fn decrypt(envelope: &CryptoEnvelope, passphrase: &str) -> Result<SecretBytes, CryptoError> {
    let salt = hex::decode(&envelope.kdfparams.salt)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let iv = hex::decode(&envelope.cipherparams.iv)
        .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let ciphertext =
        hex::decode(&envelope.ciphertext).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;
    let auth_tag =
        hex::decode(&envelope.auth_tag).map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    // Validate KDF parameters to prevent downgrade attacks.
    // Reject envelopes with weakened parameters that would make brute-forcing trivial.
    let n = envelope.kdfparams.n;
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
    if envelope.kdfparams.r < KDF_R {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt r={} is below minimum {KDF_R} — possible downgrade attack",
            envelope.kdfparams.r
        )));
    }
    if envelope.kdfparams.p < KDF_P {
        return Err(CryptoError::InvalidParams(format!(
            "scrypt p={} is below minimum {KDF_P} — possible downgrade attack",
            envelope.kdfparams.p
        )));
    }
    if envelope.kdfparams.dklen < KDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "dklen={} is below minimum {KDF_DKLEN}",
            envelope.kdfparams.dklen
        )));
    }
    if envelope.kdfparams.dklen != KDF_DKLEN {
        return Err(CryptoError::InvalidParams(format!(
            "dklen={} is unsupported, expected exactly {KDF_DKLEN}",
            envelope.kdfparams.dklen
        )));
    }

    let log_n = n.trailing_zeros() as u8;
    let params = ScryptParams::new(
        log_n,
        envelope.kdfparams.r,
        envelope.kdfparams.p,
        envelope.kdfparams.dklen as usize,
    )
    .map_err(|e| CryptoError::InvalidParams(e.to_string()))?;

    let mut derived_key = vec![0u8; envelope.kdfparams.dklen as usize];
    scrypt(passphrase.as_bytes(), &salt, &params, &mut derived_key)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
    derived_key.zeroize();
    let nonce = Nonce::from_slice(&iv);

    // Reconstruct the combined ciphertext + tag expected by aes-gcm
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
        assert_ne!(env1.kdfparams.salt, env2.kdfparams.salt);
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
        assert_eq!(deserialized.kdfparams.salt, envelope.kdfparams.salt);
        assert_eq!(deserialized.cipherparams.iv, envelope.cipherparams.iv);

        let decrypted = decrypt(&deserialized, "pass").unwrap();
        assert_eq!(decrypted.expose(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_large_payload() {
        // Regression: ensure correctness is preserved with zeroization changes
        let plaintext = vec![0xAB; 1024];
        let passphrase = "test-passphrase-for-zeroize";

        let envelope = encrypt(&plaintext, passphrase).unwrap();
        let decrypted = decrypt(&envelope, passphrase).unwrap();

        assert_eq!(decrypted.expose(), &plaintext[..]);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_still_fails() {
        // Regression: zeroization changes must not break error handling
        let plaintext = b"sensitive data";
        let envelope = encrypt(plaintext, "correct").unwrap();
        let result = decrypt(&envelope, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_dklen_above_32_should_not_panic() {
        // BUG TEST: When dklen > 32 in a tampered envelope, decrypt() panics
        // instead of returning an error because Key::<Aes256Gcm>::from_slice()
        // requires exactly 32 bytes. The validation only checks dklen >= 32,
        // so dklen = 48 passes validation but causes:
        //   derived_key = vec![0u8; 48]  (48 bytes)
        //   Key::<Aes256Gcm>::from_slice(&derived_key)  → panic! (expects 32)
        //
        // Library code must never panic on user/file input — it should return Err.
        let plaintext = b"test data";
        let mut envelope = encrypt(plaintext, "pass").unwrap();

        // Tamper: set dklen to 48 (passes the >= 32 check but panics at from_slice)
        envelope.kdfparams.dklen = 48;

        // This should return Err, not panic.
        // Use catch_unwind to detect the panic if the bug is present.
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
}
