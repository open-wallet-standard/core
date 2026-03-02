use crate::process_hardening::{mlock_slice, munlock_slice};
use zeroize::Zeroize;

/// A byte buffer that is zeroed on drop.
///
/// This is the primary type used to hold sensitive key material.
/// It ensures that the underlying bytes are securely wiped from memory
/// when the value is dropped. On Unix, the buffer is mlocked to prevent
/// swapping to disk.
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create from an owned Vec.
    pub fn new(data: Vec<u8>) -> Self {
        if !data.is_empty() {
            mlock_slice(data.as_ptr(), data.len());
        }
        SecretBytes { inner: data }
    }

    /// Create from a byte slice (copies the data).
    pub fn from_slice(data: &[u8]) -> Self {
        let inner = data.to_vec();
        if !inner.is_empty() {
            mlock_slice(inner.as_ptr(), inner.len());
        }
        SecretBytes { inner }
    }

    /// Expose the underlying bytes. Use with care.
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Returns the length of the secret data.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the secret data is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        SecretBytes::from_slice(&self.inner)
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let ptr = self.inner.as_ptr();
        let len = self.inner.len();
        self.inner.zeroize();
        munlock_slice(ptr, len);
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_doesnt_leak() {
        let secret = SecretBytes::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{:?}", secret);
        assert!(!debug.contains("DE"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
        assert!(debug.contains("[REDACTED; 4 bytes]"));
    }

    #[test]
    fn test_expose_returns_data() {
        let data = vec![1, 2, 3, 4];
        let secret = SecretBytes::new(data.clone());
        assert_eq!(secret.expose(), &data[..]);
    }

    #[test]
    fn test_from_slice() {
        let data = [5, 6, 7, 8];
        let secret = SecretBytes::from_slice(&data);
        assert_eq!(secret.expose(), &data[..]);
    }

    #[test]
    fn test_len() {
        let secret = SecretBytes::new(vec![0; 32]);
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_clone_independence() {
        let original = SecretBytes::new(vec![1, 2, 3]);
        let cloned = original.clone();
        assert_eq!(original.expose(), cloned.expose());
        // They should be independent allocations
        assert_ne!(
            original.expose().as_ptr(),
            cloned.expose().as_ptr()
        );
    }
}
