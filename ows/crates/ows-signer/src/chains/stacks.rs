use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512_256};

/// Crockford Base32 alphabet used by c32check encoding.
const C32_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Byte offset of the 65-byte VRS signature in a serialized Stacks transaction.
/// Layout: version(1) + chain_id(4) + auth_type(1) + hash_mode(1) + signer(20) +
///         nonce(8) + fee(8) + key_encoding(1) = 44
///
/// This layout applies to standard single-sig (P2PKH) spending conditions only.
/// Multi-sig and sponsored transactions have a different auth structure.
pub const STACKS_SIG_OFFSET: usize = 44;

/// Stacks chain signer (c32check addresses, secp256k1).
pub struct StacksSigner {
    /// Address version byte: 22 for mainnet (SP), 26 for testnet (ST).
    version: u8,
}

impl StacksSigner {
    pub fn new(version: u8) -> Self {
        StacksSigner { version }
    }

    pub fn mainnet() -> Self {
        Self::new(22)
    }

    pub fn testnet() -> Self {
        Self::new(26)
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    /// Hash160: RIPEMD160(SHA256(data))
    fn hash160(data: &[u8]) -> Vec<u8> {
        let sha256 = Sha256::digest(data);
        let ripemd = Ripemd160::digest(sha256);
        ripemd.to_vec()
    }

    /// Encode bytes using c32check encoding with the given version byte.
    ///
    /// 1. Compute checksum: first 4 bytes of SHA256(SHA256(version || data))
    /// 2. Encode (version || data || checksum) as a big integer in Crockford Base32
    /// 3. Prepend 'S' prefix
    fn c32check_encode(version: u8, data: &[u8]) -> String {
        // Compute checksum
        let mut check_data = Vec::with_capacity(1 + data.len());
        check_data.push(version);
        check_data.extend_from_slice(data);
        let checksum = &Sha256::digest(Sha256::digest(&check_data))[..4];

        // Build the payload: version + data + checksum
        // But c32check encodes (data + checksum) as big integer, then prepends c32-encoded version
        let mut payload = Vec::with_capacity(data.len() + 4);
        payload.extend_from_slice(data);
        payload.extend_from_slice(checksum);

        // Encode payload as big integer in base32
        let c32_chars = Self::c32_encode(&payload);

        // Encode version character
        let version_char = C32_ALPHABET[version as usize % 32] as char;

        // Prepend version and 'S' prefix
        let mut result = String::with_capacity(2 + c32_chars.len());
        result.push('S');
        result.push(version_char);
        result.push_str(&c32_chars);

        result
    }

    /// Encode a byte slice as a big integer in Crockford Base32.
    /// Preserves leading zero bytes as '0' characters.
    fn c32_encode(data: &[u8]) -> String {
        if data.is_empty() {
            return String::new();
        }

        // Count leading zeros
        let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

        // Convert bytes to base32 by treating as big integer
        // Work with the bytes as a big-endian unsigned integer
        let mut result = Vec::new();

        // Use repeated division by 32 on a mutable byte array
        let mut digits: Vec<u8> = data.to_vec();

        loop {
            if digits.is_empty() || (digits.len() == 1 && digits[0] == 0) {
                break;
            }

            // Remove leading zeros from working digits
            while digits.len() > 1 && digits[0] == 0 {
                digits.remove(0);
            }

            if digits.len() == 1 && digits[0] == 0 {
                break;
            }

            // Divide the big integer (in base-256) by 32, collecting remainder
            let mut remainder: u32 = 0;
            let mut new_digits = Vec::with_capacity(digits.len());

            for &d in &digits {
                let acc = remainder * 256 + d as u32;
                new_digits.push((acc / 32) as u8);
                remainder = acc % 32;
            }

            result.push(C32_ALPHABET[remainder as usize] as char);

            // Remove leading zeros from quotient
            while new_digits.len() > 1 && new_digits[0] == 0 {
                new_digits.remove(0);
            }

            digits = new_digits;

            if digits.len() == 1 && digits[0] == 0 {
                break;
            }
        }

        // Add leading zero characters
        result.extend(std::iter::repeat_n('0', leading_zeros));

        result.reverse();
        result.into_iter().collect()
    }
}

impl ChainSigner for StacksSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stacks
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        5757
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        // Stacks convention: 33-byte key (trailing 0x01) → compressed pubkey,
        // 32-byte key → uncompressed pubkey. Matches @stacks/transactions behavior.
        let (key_bytes, compressed) = if private_key.len() == 33 && private_key[32] == 0x01 {
            (&private_key[..32], true)
        } else {
            (private_key, false)
        };

        let signing_key = Self::signing_key(key_bytes)?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_point = verifying_key.to_encoded_point(compressed);
        let pubkey_bytes = pubkey_point.as_bytes();

        let hash = Self::hash160(pubkey_bytes);
        let address = Self::c32check_encode(self.version, &hash);

        Ok(address)
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let key_bytes = if private_key.len() == 33 && private_key[32] == 0x01 {
            &private_key[..32]
        } else {
            private_key
        };

        let signing_key = Self::signing_key(key_bytes)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        // Stacks uses VRS format: recovery_id (1 byte) || r (32 bytes) || s (32 bytes)
        let r_s = signature.to_bytes();
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.push(recovery_id.to_byte());
        sig_bytes.extend_from_slice(&r_s);

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Stacks transaction signing matches @stacks/transactions:
        //   1. Clear auth fields (nonce, fee, key_encoding, signature) to get "initial" form
        //   2. initial_sighash = SHA-512/256(cleared_tx)
        //   3. presign_hash = SHA-512/256(initial_sighash || auth_type || fee || nonce)
        //   4. sign(presign_hash)
        if tx_bytes.len() < STACKS_SIG_OFFSET + 65 {
            return Err(SignerError::InvalidTransaction(
                "stacks transaction too short".into(),
            ));
        }

        let auth_type = tx_bytes[5];
        let nonce = &tx_bytes[27..35];
        let fee = &tx_bytes[35..43];

        // 1. Clear auth fields for initial sighash (matching intoInitialSighashAuth)
        //    clearCondition zeros: nonce, fee, signature. NOT key_encoding.
        let mut cleared = tx_bytes.to_vec();
        // Zero nonce (bytes 27-34)
        cleared[27..35].fill(0);
        // Zero fee (bytes 35-42)
        cleared[35..43].fill(0);
        // key_encoding (byte 43) is NOT cleared — matches @stacks/transactions
        // Zero signature (bytes 44-108)
        cleared[STACKS_SIG_OFFSET..STACKS_SIG_OFFSET + 65].fill(0);

        // 2. Initial sighash
        let initial_sighash = Sha512_256::digest(&cleared);

        // 3. Presign hash: SHA-512/256(sighash || auth_type || fee || nonce)
        let mut presign_input = Vec::with_capacity(32 + 1 + 8 + 8);
        presign_input.extend_from_slice(&initial_sighash);
        presign_input.push(auth_type);
        presign_input.extend_from_slice(fee);
        presign_input.extend_from_slice(nonce);
        let presign_hash = Sha512_256::digest(&presign_input);

        self.sign(private_key, &presign_hash)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 65 {
            return Err(SignerError::InvalidTransaction(
                "expected 65-byte VRS signature".into(),
            ));
        }
        if tx_bytes.len() < STACKS_SIG_OFFSET + 65 {
            return Err(SignerError::InvalidTransaction(
                "stacks transaction too short".into(),
            ));
        }

        // Copy the unsigned tx and inject the VRS signature at the auth offset
        let mut signed = tx_bytes.to_vec();
        signed[STACKS_SIG_OFFSET..STACKS_SIG_OFFSET + 65]
            .copy_from_slice(&signature.signature);
        Ok(signed)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Stacks message signing: SHA-256 of prefixed message
        // Format: 0x17 + "Stacks Signed Message:\n" + length_byte + message
        if message.len() > 255 {
            return Err(SignerError::InvalidMessage(
                "stacks message signing supports max 255 bytes (single-byte length prefix)".into(),
            ));
        }

        let prefix = b"\x17Stacks Signed Message:\n";
        let mut data = Vec::with_capacity(prefix.len() + 1 + message.len());
        data.extend_from_slice(prefix);
        data.push(message.len() as u8);
        data.extend_from_slice(message);

        let hash = Sha256::digest(&data);
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/5757'/0'/0/{}", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_chain_properties() {
        let signer = StacksSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Stacks);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 5757);
    }

    #[test]
    fn test_derivation_path() {
        let signer = StacksSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/5757'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/44'/5757'/0'/0/3");
    }

    #[test]
    fn test_address_starts_with_sp_mainnet() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(
            address.starts_with("SP"),
            "mainnet address should start with SP, got: {}",
            address
        );
    }

    #[test]
    fn test_address_starts_with_st_testnet() {
        let privkey = test_privkey();
        let signer = StacksSigner::testnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(
            address.starts_with("ST"),
            "testnet address should start with ST, got: {}",
            address
        );
    }

    #[test]
    fn test_known_address_generator_point_uncompressed() {
        // Private key = 1 (secp256k1 generator point), 32 bytes → uncompressed pubkey
        // Verified against @stacks/transactions getAddressFromPrivateKey
        let privkey = test_privkey();
        let address = StacksSigner::mainnet().derive_address(&privkey).unwrap();
        assert_eq!(address, "SP28V4JZSYMM8ACMP1B38FAXG6M97P798MMKY9DW1");
    }

    #[test]
    fn test_known_address_generator_point_compressed() {
        // Private key = 1 with 0x01 suffix → compressed pubkey
        // Verified against @stacks/transactions getAddressFromPrivateKey(key + '01')
        let mut privkey = test_privkey();
        privkey.push(0x01);
        let address = StacksSigner::mainnet().derive_address(&privkey).unwrap();
        assert_eq!(address, "SP1THWXQ8368SDN2MJGE4BMDKMCHZ2GSVTS1X0BPM");
    }

    #[test]
    fn test_deterministic() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_message() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let result = signer.sign_message(&privkey, b"hello stacks").unwrap();
        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_sign_message_hash_matches_stacks_js() {
        // Verify the message hash matches @stacks/encryption hashMessage("hello stacks")
        // hashMessage = SHA-256(0x17 + "Stacks Signed Message:\n" + len + message)
        let prefix = b"\x17Stacks Signed Message:\n";
        let message = b"hello stacks";
        let mut data = Vec::new();
        data.extend_from_slice(prefix);
        data.push(message.len() as u8);
        data.extend_from_slice(message);

        let hash = Sha256::digest(&data);
        let hash_hex = hex::encode(hash);
        // This value was verified against @stacks/encryption hashMessage("hello stacks")
        assert_eq!(
            hash_hex,
            "ce0bff208ed52c820b75cbe920554a6ae3eaba703182aa15051eb108ebdca4c4"
        );
    }

    #[test]
    fn test_sign_transaction() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        // Minimal valid unsigned tx: 180 bytes with zeroed signature at offset 44
        let mut fake_tx = vec![0u8; 180];
        fake_tx[5] = 0x04; // auth_type = Standard
        let result = signer.sign_transaction(&privkey, &fake_tx).unwrap();
        assert_eq!(result.signature.len(), 65); // VRS
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_encode_signed_transaction() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let mut fake_tx = vec![0u8; 180];
        fake_tx[5] = 0x04;
        let output = signer.sign_transaction(&privkey, &fake_tx).unwrap();
        let signed = signer
            .encode_signed_transaction(&fake_tx, &output)
            .unwrap();
        // Same length, signature injected at offset 44
        assert_eq!(signed.len(), 180);
        assert_eq!(&signed[STACKS_SIG_OFFSET..STACKS_SIG_OFFSET + 65], &output.signature[..]);
        // Rest of tx unchanged
        assert_eq!(&signed[..STACKS_SIG_OFFSET], &fake_tx[..STACKS_SIG_OFFSET]);
        assert_eq!(&signed[STACKS_SIG_OFFSET + 65..], &fake_tx[STACKS_SIG_OFFSET + 65..]);
    }

    #[test]
    fn test_sign_message_rejects_long_message() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let long_msg = vec![0x41u8; 256];
        let result = signer.sign_message(&privkey, &long_msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_transaction_rejects_short_input() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let result = signer.sign_transaction(&privkey, b"too short");
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_requires_32_byte_hash() {
        let privkey = test_privkey();
        let signer = StacksSigner::mainnet();
        let result = signer.sign(&privkey, b"too short");
        assert!(result.is_err());
    }

}
