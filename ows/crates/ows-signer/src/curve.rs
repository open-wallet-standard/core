/// Elliptic curve type used by a chain signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    Secp256k1,
    Ed25519,
    /// BIP32-Ed25519 with Peikert's amendment for hierarchical deterministic
    /// key derivation over a non-linear keyspace.
    /// Unlike SLIP-10 Ed25519, this supports both hardened and non-hardened derivation.
    Ed25519Bip32,
}

impl Curve {
    /// Returns the expected private key length in bytes.
    pub fn private_key_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => 32,
            Curve::Ed25519 => 32,
            Curve::Ed25519Bip32 => 96, // full extended key: kL(32) + kR(32) + chainCode(32)
        }
    }

    /// Returns the expected public key length in bytes (compressed for secp256k1).
    pub fn public_key_len(&self) -> usize {
        match self {
            Curve::Secp256k1 => 33, // compressed
            Curve::Ed25519 => 32,
            Curve::Ed25519Bip32 => 32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_lengths_secp256k1() {
        assert_eq!(Curve::Secp256k1.private_key_len(), 32);
        assert_eq!(Curve::Secp256k1.public_key_len(), 33);
    }

    #[test]
    fn test_key_lengths_ed25519() {
        assert_eq!(Curve::Ed25519.private_key_len(), 32);
        assert_eq!(Curve::Ed25519.public_key_len(), 32);
    }

    #[test]
    fn test_key_lengths_ed25519_bip32() {
        assert_eq!(Curve::Ed25519Bip32.private_key_len(), 96);
        assert_eq!(Curve::Ed25519Bip32.public_key_len(), 32);
    }

    #[test]
    fn test_equality() {
        assert_eq!(Curve::Secp256k1, Curve::Secp256k1);
        assert_eq!(Curve::Ed25519, Curve::Ed25519);
        assert_eq!(Curve::Ed25519Bip32, Curve::Ed25519Bip32);
        assert_ne!(Curve::Secp256k1, Curve::Ed25519);
        assert_ne!(Curve::Ed25519, Curve::Ed25519Bip32);
    }
}
