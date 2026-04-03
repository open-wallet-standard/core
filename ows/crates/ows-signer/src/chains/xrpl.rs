use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::SigningKey;
use k256::PublicKey;
use ows_core::ChainType;
use xrpl::core::binarycodec::{decode as xrpl_decode, encode as xrpl_encode};
use xrpl::core::keypairs::{
    derive_classic_address, CryptoImplementation, Secp256k1 as XrplSecp256k1,
};

/// XRPL chain signer (secp256k1).
///
/// Signing algorithm: `STX\0` prefix || serialized tx fields → SHA512-half →
/// secp256k1 DER-encoded signature.
///
/// The caller passes the raw binary-encoded unsigned transaction (no prefix).
/// OWS prepends the `STX\0` signing prefix internally before hashing.
pub struct XrplSigner;

impl ChainSigner for XrplSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Xrpl
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        144
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/144'/0'/0/{}", index)
    }

    /// Derive a classic XRPL `r`-address from a private key.
    ///
    /// Algorithm: compressed pubkey → SHA256 → RIPEMD160 → base58check
    /// with version byte `0x00` using the XRP Ledger dictionary.
    ///
    /// Delegates to `xrpl::core::keypairs::derive_classic_address`.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        let pubkey_bytes = PublicKey::from(signing_key.verifying_key()).to_sec1_bytes();

        derive_classic_address(&hex::encode_upper(&pubkey_bytes))
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    /// Sign a pre-hashed 32-byte message with secp256k1 (DER output).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let digest: [u8; 32] = message.try_into().map_err(|_| {
            SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            ))
        })?;
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let sig: k256::ecdsa::Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
        Ok(SignOutput {
            signature: sig.to_der().as_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Sign a binary-encoded unsigned XRPL transaction.
    ///
    /// `tx_bytes` must be the raw binary output of the XRPL binary codec's
    /// `encode(tx)` — the serialized transaction fields with no hash prefix.
    ///
    /// Internally prepends the XRPL single-signing prefix `STX\0` (0x53545800),
    /// then delegates to `xrpl::core::keypairs::Secp256k1::sign` which computes
    /// SHA512-half and produces a DER-encoded secp256k1 signature.
    ///
    /// Returns a `SignOutput` with the DER signature and the compressed public key
    /// (33 bytes), both required by `encode_signed_transaction`.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "transaction bytes must not be empty".into(),
            ));
        }

        // Validate private key before signing.
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        // STX\0 (0x53545800) is the XRPL single-signing hash prefix. It is prepended
        // to the serialized fields before SHA512-half, matching the XRPL signing spec.
        let mut prefixed = Vec::with_capacity(4 + tx_bytes.len());
        prefixed.extend_from_slice(&[0x53, 0x54, 0x58, 0x00]);
        prefixed.extend_from_slice(tx_bytes);

        // xrpl-rust's Secp256k1::sign hashes with SHA512-half internally.
        // The key format expected is "00"-prefixed uppercase hex (secp256k1 convention).
        let privkey_hex = format!("00{}", hex::encode_upper(private_key));
        let sig_bytes = XrplSecp256k1
            .sign(&prefixed, &privkey_hex)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: None,
            public_key: None,
        })
    }

    /// Encode a fully-signed XRPL transaction ready for broadcast.
    ///
    /// `tx_bytes` must be the same binary-encoded unsigned transaction passed to
    /// `sign_transaction` (no STX\0 prefix). The binary already contains `SigningPubKey`;
    /// this method only injects `TxnSignature` into the decoded JSON before re-encoding.
    ///
    /// Decodes the binary to JSON via `xrpl::core::binarycodec::decode`, injects
    /// `TxnSignature`, then re-encodes to canonical XRPL binary via `encode`. The
    /// returned bytes can be uppercase-hex-encoded and submitted as `tx_blob` to
    /// the XRPL `submit` JSON-RPC method.
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // Convert binary bytes to hex string for xrpl_decode.
        let tx_hex = hex::encode_upper(tx_bytes);
        let mut json_tx = xrpl_decode(&tx_hex)
            .map_err(|e| SignerError::InvalidTransaction(format!("xrpl decode failed: {}", e)))?;

        json_tx["TxnSignature"] =
            serde_json::Value::String(hex::encode_upper(&signature.signature));

        let hex_encoded = xrpl_encode(&json_tx)
            .map_err(|e| SignerError::InvalidTransaction(format!("xrpl encode failed: {}", e)))?;

        hex::decode(&hex_encoded)
            .map_err(|e| SignerError::InvalidTransaction(format!("invalid hex from encode: {}", e)))
    }

    /// Off-chain message signing is not yet supported for XRPL.
    ///
    /// XRPL has no canonical message signing standard equivalent to EIP-191.
    /// A convention must be defined before this can be implemented.
    fn sign_message(
        &self,
        _private_key: &[u8],
        _message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::SigningFailed(
            "XRPL off-chain message signing is not supported: no canonical standard exists. \
             Define a convention (e.g. SHA512Half(XMSG\\0 || message)) before enabling this."
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use sha2::{Digest, Sha512};

    /// XRPL hash function: first 32 bytes of SHA-512.
    /// Used only in tests to verify sign_transaction's internal hashing.
    fn sha512_half(data: &[u8]) -> [u8; 32] {
        let hash = Sha512::digest(data);
        hash[..32].try_into().expect("sha512 output is 64 bytes")
    }

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Known test private key (32 bytes).
    fn test_privkey() -> Vec<u8> {
        // Derived from abandon mnemonic at m/44'/144'/0'/0/0 with secp256k1
        // via OWS HD derivation (BIP-32/44, coin type 144).
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = XrplSigner;
        let path = signer.default_derivation_path(0);
        HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Secp256k1)
            .unwrap()
            .expose()
            .to_vec()
    }

    #[test]
    fn test_chain_properties() {
        let signer = XrplSigner;
        assert_eq!(signer.chain_type(), ChainType::Xrpl);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 144);
    }

    #[test]
    fn test_derivation_path() {
        let signer = XrplSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/144'/0'/0/0");
        assert_eq!(signer.default_derivation_path(1), "m/44'/144'/0'/0/1");
        assert_eq!(signer.default_derivation_path(5), "m/44'/144'/0'/0/5");
    }

    #[test]
    fn test_derive_address_format() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let address = signer.derive_address(&privkey).unwrap();

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
    fn test_derive_address_known_vector() {
        // Known vector: OWS HD derivation from abandon mnemonic at m/44'/144'/0'/0/0
        // produces a classic r-address verified against the XRPL test suite.
        let privkey = test_privkey();
        let signer = XrplSigner;
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(address, "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3");
    }

    #[test]
    fn test_derive_address_deterministic() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_sign_transaction_single() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let tx_bytes = b"fake_unsigned_tx_bytes";

        let result = signer.sign_transaction(&privkey, tx_bytes).unwrap();

        // DER signature starts with 0x30
        assert_eq!(result.signature[0], 0x30, "expected DER sequence tag 0x30");
        // secp256k1 DER signatures are 70-72 bytes
        assert!(
            result.signature.len() >= 70 && result.signature.len() <= 72,
            "unexpected DER signature length: {}",
            result.signature.len()
        );
        assert!(result.recovery_id.is_none());
        // SigningPubKey is already embedded in tx_bytes; sign_transaction does not return it.
        assert!(result.public_key.is_none());
    }

    #[test]
    fn test_sign_transaction_deterministic() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let tx_bytes = b"deterministic_test_tx";

        let sig1 = signer.sign_transaction(&privkey, tx_bytes).unwrap();
        let sig2 = signer.sign_transaction(&privkey, tx_bytes).unwrap();
        assert_eq!(
            sig1.signature, sig2.signature,
            "secp256k1 (RFC6979) must be deterministic"
        );
    }

    #[test]
    fn test_sign_transaction_empty_input_errors() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        assert!(signer.sign_transaction(&privkey, b"").is_err());
    }

    #[test]
    fn test_sign_transaction_equals_sign_of_sha512_half() {
        // sign_transaction(privkey, bytes) must equal sign(privkey, sha512_half(STX\0 || bytes))
        // because sign_transaction internally prepends the STX\0 prefix before hashing.
        let privkey = test_privkey();
        let signer = XrplSigner;
        let tx_bytes = b"some_unsigned_tx_bytes";

        let sig_tx = signer.sign_transaction(&privkey, tx_bytes).unwrap();

        let mut prefixed = vec![0x53, 0x54, 0x58, 0x00];
        prefixed.extend_from_slice(tx_bytes);
        let digest = sha512_half(&prefixed);
        let sig_direct = signer.sign(&privkey, &digest).unwrap();

        assert_eq!(
            sig_tx.signature, sig_direct.signature,
            "sign_transaction must be equivalent to sign(sha512_half(STX\\0 || bytes))"
        );
    }

    #[test]
    fn test_sign_raw_32_byte_hash() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let hash = sha512_half(b"test message");
        let result = signer.sign(&privkey, &hash).unwrap();
        assert_eq!(result.signature[0], 0x30);
    }

    #[test]
    fn test_sign_rejects_non_32_byte_hash() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        assert!(signer.sign(&privkey, b"too short").is_err());
        assert!(signer.sign(&privkey, &[0u8; 33]).is_err());
    }

    #[test]
    fn test_sign_message_unsupported() {
        let privkey = test_privkey();
        let signer = XrplSigner;
        let result = signer.sign_message(&privkey, b"hello");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not supported"),
            "error should mention 'not supported', got: {}",
            err
        );
    }

    #[test]
    fn test_derive_address_invalid_key() {
        let signer = XrplSigner;
        assert!(signer.derive_address(&[0u8; 16]).is_err());
        assert!(signer.derive_address(&[]).is_err());
    }

    /// Known signing vector using a fixed seed's private key.
    ///
    /// tx_bytes = binary-encoded unsigned Payment tx (no STX\0 prefix)
    /// expected_sig = expected DER signature for TxnSignature
    #[test]
    fn test_sign_transaction_matches_known_vector() {
        let signer = XrplSigner;

        // Raw 32-byte secp256k1 private key (seed: "sEdTM1uX8pu2do5XvTnutH6HsouMaM2").
        let privkey =
            hex::decode("AA83B3DC1205119B4B6F09CF9895C9359B56F5A81BB9BB0450C87BE041113B58")
                .unwrap();

        // Binary-encoded unsigned Payment tx — no STX\0 prefix.
        let tx_bytes = hex::decode("12000024000000016140000000000F424068400000000000000C7321035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D98114B22CCE5BFD693ED7FA15B57B6B5370551B7E6DB58314F667B0CA50CC7709A220B0561B85E53A48461FA8").unwrap();

        let result = signer.sign_transaction(&privkey, &tx_bytes).unwrap();

        let expected_sig = "3045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B13";
        assert_eq!(hex::encode_upper(&result.signature), expected_sig);
        assert!(result.public_key.is_none());
    }

    /// Known vector: encode_signed_transaction injects SigningPubKey
    /// into the binary tx and re-encodes to the canonical tx_blob expected by submit.
    ///
    /// tx_bytes and signature match the vector used in test_sign_transaction_matches_known_vector.
    #[test]
    fn test_encode_signed_transaction_matches_known_vector() {
        let signer = XrplSigner;

        // Binary-encoded unsigned tx — same vector as test_sign_transaction_matches_known_vector.
        let tx_bytes = hex::decode("12000024000000016140000000000F424068400000000000000C7321035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D98114B22CCE5BFD693ED7FA15B57B6B5370551B7E6DB58314F667B0CA50CC7709A220B0561B85E53A48461FA8").unwrap();

        let signature = hex::decode("3045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B13").unwrap();

        let sign_output = SignOutput {
            signature,
            recovery_id: None,
            public_key: None,
        };

        let encoded = signer
            .encode_signed_transaction(&tx_bytes, &sign_output)
            .unwrap();

        let expected_tx_blob = "12000024000000016140000000000F424068400000000000000C7321035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D974473045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B138114B22CCE5BFD693ED7FA15B57B6B5370551B7E6DB58314F667B0CA50CC7709A220B0561B85E53A48461FA8";

        assert_eq!(hex::encode_upper(&encoded), expected_tx_blob);
    }

    #[test]
    fn test_encode_signed_transaction_invalid_tx_bytes() {
        let signer = XrplSigner;
        let tx_bytes = b"not valid xrpl binary codec";
        let sign_output = SignOutput {
            signature: vec![0x30],
            recovery_id: None,
            public_key: None,
        };
        let err = signer
            .encode_signed_transaction(tx_bytes, &sign_output)
            .unwrap_err();
        assert!(
            err.to_string().contains("xrpl decode failed"),
            "expected 'xrpl decode failed' error, got: {}",
            err
        );
    }

    #[test]
    fn test_sign_transaction_invalid_privkey() {
        let signer = XrplSigner;
        let tx_bytes = b"some_tx_bytes";
        assert!(signer.sign_transaction(&[], tx_bytes).is_err());
        assert!(signer.sign_transaction(&[0u8; 16], tx_bytes).is_err());
    }
}
