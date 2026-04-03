use sha2::{Digest, Sha256};
use sharks::{Share, Sharks};

use crate::error::GuardianError;

pub fn split_secret(
    secret: &[u8],
    threshold: u8,
    total: u8,
) -> Result<Vec<Vec<u8>>, GuardianError> {
    if threshold < 2 {
        return Err(GuardianError::InvalidThreshold(
            "threshold must be at least 2".into(),
        ));
    }
    if threshold > total {
        return Err(GuardianError::InvalidThreshold(format!(
            "threshold ({}) cannot exceed total guardians ({})",
            threshold, total
        )));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(secret);
    let shares: Vec<Share> = dealer.take(total as usize).collect();

    let encoded: Vec<Vec<u8>> = shares.iter().map(|s| Vec::from(s)).collect();

    Ok(encoded)
}

pub fn reconstruct_secret(
    shares_bytes: &[Vec<u8>],
    threshold: u8,
) -> Result<Vec<u8>, GuardianError> {
    let shares: Vec<Share> = shares_bytes
        .iter()
        .map(|bytes| Share::try_from(bytes.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| GuardianError::ShamirReconstructFailed(format!("{}", e)))?;

    let sharks = Sharks(threshold);
    let secret = sharks
        .recover(&shares)
        .map_err(|e| GuardianError::ShamirReconstructFailed(format!("{}", e)))?;

    Ok(secret)
}

pub fn hash_secret(secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let shares = split_secret(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        let recovered = reconstruct_secret(&shares[..2], 2).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_reconstruct_with_different_share_combinations() {
        let secret = b"test secret mnemonic phrase";
        let shares = split_secret(secret, 2, 3).unwrap();

        let r1 = reconstruct_secret(&[shares[0].clone(), shares[1].clone()], 2).unwrap();
        let r2 = reconstruct_secret(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
        let r3 = reconstruct_secret(&[shares[1].clone(), shares[2].clone()], 2).unwrap();

        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_hash_secret() {
        let secret = b"hello";
        let h = hash_secret(secret);
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_hash_verification() {
        let secret = b"my mnemonic phrase";
        let original_hash = hash_secret(secret);

        let shares = split_secret(secret, 2, 3).unwrap();
        let recovered = reconstruct_secret(&shares[..2], 2).unwrap();
        let recovered_hash = hash_secret(&recovered);

        assert_eq!(original_hash, recovered_hash);
    }

    #[test]
    fn test_threshold_too_low() {
        let result = split_secret(b"secret", 1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_threshold_exceeds_total() {
        let result = split_secret(b"secret", 4, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_3_of_5_scheme() {
        let secret = b"a]longer secret that simulates a real mnemonic phrase with many words";
        let shares = split_secret(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = reconstruct_secret(&shares[..3], 3).unwrap();
        assert_eq!(recovered, secret);
    }
}
