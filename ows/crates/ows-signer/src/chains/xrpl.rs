use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::SigningKey;
use k256::PublicKey;
use ows_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use xrpl::core::binarycodec::encode as xrpl_encode;

/// XRPL chain signer (secp256k1).
///
/// Signing algorithm: `STX\0` prefix || serialized tx fields → SHA512-half →
/// secp256k1 DER-encoded signature.
///
/// The caller passes the raw serialized transaction bytes (output of
/// `ripple-binary-codec`'s `encode(tx)` — no prefix). OWS prepends the
/// `STX\0` signing prefix internally.
pub struct XrplSigner;

/// XRPL hash function: first 32 bytes of SHA-512.
///
/// Equivalent to `sha512Half` in ripple-binary-codec/src/hashes.ts.
fn sha512_half(data: &[u8]) -> [u8; 32] {
    let hash = Sha512::digest(data);
    hash[..32].try_into().expect("sha512 output is 64 bytes")
}

/// Sign a 32-byte digest with secp256k1, returning a DER-encoded signature.
///
/// XRPL requires DER encoding (not raw r||s). `k256` provides this via
/// `to_der()` on the `Signature` type.
fn sign_secp256k1(private_key: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, SignerError> {
    let signing_key = SigningKey::from_slice(private_key)
        .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
    let sig: k256::ecdsa::Signature = signing_key
        .sign_prehash(digest)
        .map_err(|e| SignerError::SigningFailed(e.to_string()))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

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
    /// with version byte `0x00` using the Ripple alphabet.
    ///
    /// Equivalent to `deriveAddressFromBytes` in ripple-keypairs/src/index.ts.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = PublicKey::from(verifying_key).to_sec1_bytes(); // compressed, 33 bytes

        let sha256 = Sha256::digest(&pubkey_bytes);
        let account_id = Ripemd160::digest(sha256);

        // Base58Check: version byte 0x00 || 20-byte account_id
        let mut payload = Vec::with_capacity(21);
        payload.push(0x00u8);
        payload.extend_from_slice(&account_id);

        Ok(bs58::encode(payload)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .with_check()
            .into_string())
    }

    /// Sign a pre-hashed 32-byte message with secp256k1 (DER output).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let digest: [u8; 32] = message.try_into().map_err(|_| {
            SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            ))
        })?;
        let sig = sign_secp256k1(private_key, &digest)?;
        Ok(SignOutput {
            signature: sig,
            recovery_id: None,
            public_key: None,
        })
    }

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

        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;
        let pubkey_bytes = PublicKey::from(signing_key.verifying_key()).to_sec1_bytes();

        // Prepend the XRPL single-signing hash prefix before hashing.
        // Equivalent to ripple-binary-codec's encodeForSigning() which prepends
        // STX\0 (0x53545800) to the serialized fields before SHA512-half.
        let mut prefixed = Vec::with_capacity(4 + tx_bytes.len());
        prefixed.extend_from_slice(&[0x53, 0x54, 0x58, 0x00]);
        prefixed.extend_from_slice(tx_bytes);

        let digest = sha512_half(&prefixed);
        let sig: k256::ecdsa::Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        Ok(SignOutput {
            signature: sig.to_der().as_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes.to_vec()),
        })
    }

    /// Encode a fully-signed XRPL transaction ready for broadcast.
    ///
    /// `tx_bytes` must be the UTF-8 JSON of the unsigned transaction — the same
    /// bytes passed to `sign_transaction`. `signature` must include `public_key`
    /// (populated by `sign_transaction`).
    ///
    /// Sets `TxnSignature` and `SigningPubKey` in the JSON, then serialises to
    /// XRPL canonical binary via xrpl-rust's `encode()`. The returned bytes can
    /// be uppercase-hex-encoded and submitted as `tx_blob` to the XRPL `submit`
    /// JSON-RPC method.
    ///
    /// TODO: accept binary-encoded unsigned transaction bytes directly instead of
    /// JSON once xrpl-rust exposes a public `decode()` function.
    /// Track: https://github.com/XRPLF/xrpl-rust/issues/140
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        let pubkey = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction(
                "public_key missing from SignOutput; use sign_transaction to produce it".into(),
            )
        })?;

        let mut json_tx: serde_json::Value =
            serde_json::from_slice(tx_bytes).map_err(|e| {
                SignerError::InvalidTransaction(format!("invalid JSON transaction: {}", e))
            })?;

        json_tx["TxnSignature"] = serde_json::Value::String(hex::encode_upper(&signature.signature));
        json_tx["SigningPubKey"] = serde_json::Value::String(hex::encode_upper(pubkey));

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

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Known test private key (32 bytes).
    fn test_privkey() -> Vec<u8> {
        // Derived from abandon mnemonic at m/44'/144'/0'/0/0 with secp256k1
        // via xrpl.js: Wallet.fromMnemonic(ABANDON_PHRASE, { derivationPath: "m/44'/144'/0'/0/0", algorithm: ECDSA.secp256k1 })
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
        // Expected address from xrpl.js:
        // Wallet.fromMnemonic("abandon abandon...", {
        //   derivationPath: "m/44'/144'/0'/0/0",
        //   algorithm: ECDSA.secp256k1
        // }).classicAddress
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
        // sign_transaction populates public_key (compressed secp256k1, 33 bytes)
        assert_eq!(result.public_key.as_ref().map(|k| k.len()), Some(33));
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

    /// Cross-language vector: values produced by xrpl.js test-xrpl-signing.mjs
    /// using Wallet.fromSeed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2", { algorithm: ECDSA.secp256k1 })
    ///
    /// sign_tx_bytes = encode(tx) output — plain serialized fields, no hash prefix
    /// expected_sig  = TxnSignature from wallet.sign(tx) in xrpl.js
    ///
    /// OWS prepends STX\0 internally, so passing encode(tx) bytes produces the
    /// same signature as xrpl.js passing encodeForSigning(tx) bytes.
    #[test]
    fn test_sign_transaction_matches_xrpl_js() {
        let signer = XrplSigner;

        // Private key from Wallet.fromSeed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2")
        // xrpl.js prefixes secp256k1 keys with 0x00; strip it to get raw 32 bytes.
        let privkey =
            hex::decode("AA83B3DC1205119B4B6F09CF9895C9359B56F5A81BB9BB0450C87BE041113B58")
                .unwrap();

        // encode(tx) from ripple-binary-codec — no STX\0 prefix.
        let tx_bytes = hex::decode("12000024000000016140000000000F424068400000000000000C7321035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D98114B22CCE5BFD693ED7FA15B57B6B5370551B7E6DB58314F667B0CA50CC7709A220B0561B85E53A48461FA8").unwrap();

        let result = signer.sign_transaction(&privkey, &tx_bytes).unwrap();

        let expected_sig = "3045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B13";
        assert_eq!(
            hex::encode_upper(&result.signature),
            expected_sig,
            "sign_transaction must produce the same TxnSignature as xrpl.js"
        );
        assert_eq!(
            hex::encode_upper(result.public_key.as_ref().unwrap()),
            "035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D9"
        );
    }

    /// Cross-language vector: values produced by xrpl.js test-xrpl-signing.mjs
    /// using Wallet.fromSeed("sEdTM1uX8pu2do5XvTnutH6HsouMaM2", { algorithm: ECDSA.secp256k1 })
    ///
    /// tx_bytes  = JSON of unsigned tx (with SigningPubKey, without TxnSignature)
    /// signature = TxnSignature from wallet.sign(tx) in xrpl.js
    /// expected  = tx_blob from wallet.sign(tx) in xrpl.js
    #[test]
    fn test_encode_signed_transaction_matches_xrpl_js() {
        let signer = XrplSigner;

        let tx_bytes = hex::decode("7b225472616e73616374696f6e54797065223a225061796d656e74222c224163636f756e74223a2272484561784c72687139745a6250334d7632747275324a686b46666b4e4548593731222c2244657374696e6174696f6e223a2272505431536a7132594772424d5474745834475a486a4b75396479667a6270415965222c22416d6f756e74223a2231303030303030222c22466565223a223132222c2253657175656e6365223a312c225369676e696e675075624b6579223a22303335443838393243393944344631374232373735454334323845443635423633333541354435383841433230353742383143384333384335394337324236384439227d").unwrap();

        let signature = hex::decode("3045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B13").unwrap();
        let public_key = hex::decode("035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D9").unwrap();

        let sign_output = SignOutput {
            signature,
            recovery_id: None,
            public_key: Some(public_key),
        };

        let encoded = signer
            .encode_signed_transaction(&tx_bytes, &sign_output)
            .unwrap();

        let expected_tx_blob = "12000024000000016140000000000F424068400000000000000C7321035D8892C99D4F17B2775EC428ED65B6335A5D588AC2057B81C8C38C59C72B68D974473045022100AEBCB8F0C9AD93782F5E082B5B96E06FE8A05E14858B24A348E1C330BCAC1ED50220109D79503119EE830253A12122D1C4333F2038FB81C76B84C670BF4DCD986B138114B22CCE5BFD693ED7FA15B57B6B5370551B7E6DB58314F667B0CA50CC7709A220B0561B85E53A48461FA8";

        assert_eq!(
            hex::encode_upper(&encoded),
            expected_tx_blob,
            "encode_signed_transaction must produce the same tx_blob as xrpl.js"
        );
    }
}
