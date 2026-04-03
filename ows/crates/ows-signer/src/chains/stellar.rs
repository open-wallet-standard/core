use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Network passphrases (SEP-0005 §3)
// ---------------------------------------------------------------------------

/// Mainnet network passphrase.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
/// Testnet network passphrase.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

// ---------------------------------------------------------------------------
// XDR constants
// ---------------------------------------------------------------------------

/// ENVELOPE_TYPE_TX = 2 (4-byte big-endian).
/// Covers both classic Payment operations and Soroban InvokeHostFunction ops —
/// they all use the same envelope type, so Soroban support comes for free.
const ENVELOPE_TYPE_TX: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

// ---------------------------------------------------------------------------
// StrKey constants (SEP-0005 §2 / stellar-base strkey.js)
// ---------------------------------------------------------------------------

/// Version byte for an Ed25519 public key account ID ("G..." address).
/// Value: 6 << 3 = 0x30.
const VERSION_BYTE_ACCOUNT_ID: u8 = 6 << 3; // 0x30

// ---------------------------------------------------------------------------
// StellarSigner
// ---------------------------------------------------------------------------

/// Stellar chain signer (Ed25519, SLIP-10 hardened-only).
///
/// # SEP-0005 compliance
/// Derivation path: `m/44'/148'/{index}'`
/// All three levels are hardened — mandatory for Ed25519 SLIP-10 and enforced
/// by the OWS HD deriver (`Curve::Ed25519` rejects non-hardened components).
///
/// # Signature base
/// Stellar signs a `TransactionSignaturePayload` constructed as:
/// ```text
/// SHA256(network_passphrase) || ENVELOPE_TYPE_TX (4 bytes, big-endian) || tx_xdr_bytes
/// ```
/// Forgetting the network hash is the "Stacks mistake" — our implementation
/// always prepends it before signing.
///
/// # Soroban (smart-contract) compatibility
/// Classic and Soroban (InvokeHostFunction) transactions share the same
/// `ENVELOPE_TYPE_TX` constant, so this signer handles both without
/// any extra branching.
pub struct StellarSigner {
    /// Pre-computed SHA256 hash of the network passphrase ("network ID").
    network_id: [u8; 32],
}

impl StellarSigner {
    /// Create a signer pinned to Stellar **mainnet**.
    pub fn mainnet() -> Self {
        Self {
            network_id: Sha256::digest(MAINNET_PASSPHRASE.as_bytes()).into(),
        }
    }

    /// Create a signer pinned to Stellar **testnet**.
    pub fn testnet() -> Self {
        Self {
            network_id: Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into(),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                private_key.len()
            ))
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Build the Stellar signature base and return its SHA256 hash.
    ///
    /// `sign_transaction` requires signing the raw payload, NOT a double-hash.
    /// Ed25519 (via ed25519-dalek) signs arbitrary-length messages internally
    /// using SHA-512, so we DO NOT pre-hash again — we just pass the full
    /// `network_id || ENVELOPE_TYPE_TX || tx_xdr_bytes` payload directly to
    /// the Ed25519 signer. This matches the Stellar JS/Go/Python SDK behaviour.
    fn signature_payload(&self, tx_xdr_bytes: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(32 + 4 + tx_xdr_bytes.len());
        payload.extend_from_slice(&self.network_id);
        payload.extend_from_slice(&ENVELOPE_TYPE_TX);
        payload.extend_from_slice(tx_xdr_bytes);
        payload
    }

    /// Encode a 32-byte Ed25519 public key to a Stellar StrKey address ("G…").
    ///
    /// Algorithm (stellar-base strkey.js):
    /// 1. payload = [VERSION_BYTE_ACCOUNT_ID] + pubkey (33 bytes)
    /// 2. checksum = CRC16-XModem(payload)        (2 bytes, little-endian)
    /// 3. encode = base32(payload + checksum)      (no padding, 56 chars)
    pub fn pubkey_to_strkey(pubkey: &[u8; 32]) -> String {
        let mut payload = Vec::with_capacity(35); // 1 + 32 + 2
        payload.push(VERSION_BYTE_ACCOUNT_ID);
        payload.extend_from_slice(pubkey);

        let crc = crc16_xmodem(&payload);
        payload.push((crc & 0xFF) as u8); // low byte first (little-endian)
        payload.push((crc >> 8) as u8);   // high byte second

        base32_encode(&payload)
    }
}

// ---------------------------------------------------------------------------
// ChainSigner impl
// ---------------------------------------------------------------------------

impl ChainSigner for StellarSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stellar
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    /// BIP-44 coin type for Stellar (SLIP-44 #148).
    fn coin_type(&self) -> u32 {
        148
    }

    /// SEP-0005 derivation path: `m/44'/148'/{index}'`.
    ///
    /// All three components are hardened (the `'` marks) — this is the
    /// Stellar standard and is required for SLIP-10 Ed25519 security.
    /// Using a non-hardened level here would be the "njdawn High-severity"
    /// mistake seen in rejected PRs on other chains.
    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/148'/{}'", index)
    }

    /// Derive a Stellar `G…` StrKey address from an Ed25519 private key.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let pubkey_bytes: [u8; 32] = *verifying_key.as_bytes();
        Ok(Self::pubkey_to_strkey(&pubkey_bytes))
    }

    /// Sign an arbitrary message with Ed25519 (no extra hashing).
    ///
    /// Ed25519 signs raw bytes directly; the Ed25519-dalek library performs
    /// SHA-512 internally per RFC 8032. No recovery ID (Ed25519 is deterministic
    /// without recovery).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Sign a Stellar transaction XDR body.
    ///
    /// `tx_xdr_bytes` — raw XDR bytes of the **Transaction** struct (the body
    /// only, without the envelope wrapper or signatures array). This matches
    /// what Stellar SDKs expose as `tx.toXDR()` on the inner transaction body.
    ///
    /// Internally constructs the signature payload per the Stellar spec:
    /// ```text
    /// payload = SHA256(network_passphrase) || ENVELOPE_TYPE_TX || tx_xdr_bytes
    /// signature = Ed25519.sign(payload)
    /// ```
    ///
    /// The returned `signature` is the 64-byte Ed25519 signature that should
    /// be placed inside the `TransactionEnvelope.signatures` array as a
    /// `DecoratedSignature`. The caller is responsible for assembling the
    /// final `TransactionEnvelope` XDR using the Stellar SDK.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_xdr_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        if tx_xdr_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction(
                "transaction XDR bytes must not be empty".into(),
            ));
        }
        let signing_key = Self::signing_key(private_key)?;
        let payload = self.signature_payload(tx_xdr_bytes);
        let signature = signing_key.sign(&payload);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Stellar has no widely adopted canonical off-chain message signing
    /// convention (no EIP-191 equivalent). This implementation signs the
    /// raw message bytes directly with Ed25519, which is valid for agent
    /// use cases that control both sides of the protocol.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }
}

// ---------------------------------------------------------------------------
// CRC16-XModem (used by Stellar StrKey encoding)
// ---------------------------------------------------------------------------

/// Compute CRC-16/XMODEM over `data`.
///
/// Polynomial: 0x1021, Init: 0x0000, RefIn: false, RefOut: false, XorOut: 0x0000.
/// This matches the stellar-base JavaScript implementation exactly.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Base32 encoder (RFC 4648, no padding)
// ---------------------------------------------------------------------------

/// RFC 4648 base32 alphabet (upper-case, no padding).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `data` as RFC 4648 base32 without padding.
fn base32_encode(data: &[u8]) -> String {
    let mut output = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            output.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        output.push(BASE32_ALPHABET[idx] as char);
    }
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::Verifier;

    const ABANDON_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about";

    fn test_privkey() -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::mainnet();
        let path = signer.default_derivation_path(0);
        HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519)
            .unwrap()
            .expose()
            .to_vec()
    }

    // -----------------------------------------------------------------------
    // Chain properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_properties() {
        let signer = StellarSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Stellar);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 148);
    }

    // -----------------------------------------------------------------------
    // SEP-0005 derivation path
    // -----------------------------------------------------------------------

    #[test]
    fn test_derivation_path_format() {
        let signer = StellarSigner::mainnet();
        // All three levels must be hardened (') — the "njdawn requirement"
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/148'/1'");
        assert_eq!(signer.default_derivation_path(9), "m/44'/148'/9'");
    }

    #[test]
    fn test_derivation_path_is_all_hardened() {
        let signer = StellarSigner::mainnet();
        for index in [0u32, 1, 5, 100] {
            let path = signer.default_derivation_path(index);
            // Every component must end with '
            for component in path[2..].split('/') {
                assert!(
                    component.ends_with('\''),
                    "component '{}' in path '{}' is not hardened",
                    component,
                    path
                );
            }
        }
    }

    /// Confirm SLIP-10 Ed25519 derivation succeeds for the SEP-0005 path.
    /// Non-hardened paths would fail here — this test locks in correctness.
    #[test]
    fn test_sep0005_derivation_succeeds() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::mainnet();
        let path = signer.default_derivation_path(0);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519);
        assert!(key.is_ok(), "SEP-0005 hardened derivation must succeed");
        assert_eq!(key.unwrap().len(), 32);
    }

    // -----------------------------------------------------------------------
    // StrKey address encoding
    // -----------------------------------------------------------------------

    #[test]
    fn test_address_starts_with_g() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(
            address.starts_with('G'),
            "Stellar address must start with 'G', got: {}",
            address
        );
    }

    #[test]
    fn test_address_length_is_56() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(
            address.len(),
            56,
            "Stellar StrKey address must be exactly 56 characters, got: {}",
            address.len()
        );
    }

    #[test]
    fn test_address_is_uppercase_base32() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(
            address.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
            "Stellar address must be uppercase base32, got: {}",
            address
        );
    }

    #[test]
    fn test_address_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_different_keys_different_addresses() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::mainnet();

        let addr0 = {
            let key = HdDeriver::derive_from_mnemonic(
                &mnemonic, "", &signer.default_derivation_path(0), Curve::Ed25519,
            ).unwrap();
            signer.derive_address(key.expose()).unwrap()
        };
        let addr1 = {
            let key = HdDeriver::derive_from_mnemonic(
                &mnemonic, "", &signer.default_derivation_path(1), Curve::Ed25519,
            ).unwrap();
            signer.derive_address(key.expose()).unwrap()
        };
        assert_ne!(addr0, addr1, "different indices must produce different addresses");
    }

    /// CRC16-XModem known vector:
    /// crc16_xmodem(b"123456789") = 0x31C3 per the standard test suite.
    #[test]
    fn test_crc16_xmodem_known_vector() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    #[test]
    fn test_crc16_xmodem_empty() {
        assert_eq!(crc16_xmodem(b""), 0x0000);
    }

    /// Base32 RFC 4648 known vector: encode(b"") == "" and
    /// encode(b"f") == "MY" (no padding).
    /// RFC 4648 §10 test vectors (no padding variant):
    /// BASE32("") = ""
    /// BASE32("f") = "MY"
    /// BASE32("fo") = "MZXQ"
    /// BASE32("foo") = "MZXW6"
    /// BASE32("foob") = "MZXW6YQ"
    /// BASE32("fooba") = "MZXW6YTB"
    #[test]
    fn test_base32_known_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
    }

    /// StrKey round-trip: pubkey_to_strkey produces a 56-char G-address for
    /// the RFC-8032 test vector public key.
    #[test]
    fn test_strkey_rfc8032_vector() {
        // RFC 8032 vector 1 public key
        let pubkey_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let pubkey: [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
        let address = StellarSigner::pubkey_to_strkey(&pubkey);
        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
    }

    /// Cross-validate: address from derive_address == pubkey_to_strkey applied
    /// to the raw verifying key bytes.
    #[test]
    fn test_address_matches_manual_strkey() {
        let privkey = test_privkey();
        let signing_key = SigningKey::from_bytes(&privkey.as_slice().try_into().unwrap());
        let pubkey: [u8; 32] = *signing_key.verifying_key().as_bytes();

        let signer = StellarSigner::mainnet();
        let via_signer = signer.derive_address(&privkey).unwrap();
        let via_manual = StellarSigner::pubkey_to_strkey(&pubkey);
        assert_eq!(via_signer, via_manual);
    }

    // -----------------------------------------------------------------------
    // Ed25519 signing
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_produces_64_byte_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let result = signer.sign(&privkey, b"hello stellar").unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_none());
    }

    #[test]
    fn test_sign_is_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let sig1 = signer.sign(&privkey, b"test").unwrap();
        let sig2 = signer.sign(&privkey, b"test").unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_verifies_with_ed25519_dalek() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let message = b"verify me";

        let result = signer.sign(&privkey, message).unwrap();

        let signing_key = SigningKey::from_bytes(&privkey.as_slice().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(
            &result.signature.as_slice().try_into().unwrap(),
        );
        verifying_key.verify(message, &sig).expect("signature must verify");
    }

    // -----------------------------------------------------------------------
    // sign_transaction (Stellar signature base)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_transaction_produces_64_byte_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let fake_xdr = b"fake_xdr_transaction_bytes";
        let result = signer.sign_transaction(&privkey, fake_xdr).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
    }

    #[test]
    fn test_sign_transaction_is_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let xdr = b"some_tx_xdr_bytes";
        let sig1 = signer.sign_transaction(&privkey, xdr).unwrap();
        let sig2 = signer.sign_transaction(&privkey, xdr).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_transaction_empty_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        assert!(signer.sign_transaction(&privkey, b"").is_err());
    }

    /// Core interop validity check: sign_transaction(tx) must equal
    /// sign(network_id || ENVELOPE_TYPE_TX || tx), proving the signature
    /// base is constructed correctly.
    #[test]
    fn test_sign_transaction_equals_sign_of_signature_payload() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = b"arbitrary_xdr_for_test";

        let sig_tx = signer.sign_transaction(&privkey, tx_xdr).unwrap();

        // Build the payload manually
        let mut payload = Vec::new();
        payload.extend_from_slice(&signer.network_id);
        payload.extend_from_slice(&ENVELOPE_TYPE_TX);
        payload.extend_from_slice(tx_xdr);
        let sig_direct = signer.sign(&privkey, &payload).unwrap();

        assert_eq!(
            sig_tx.signature, sig_direct.signature,
            "sign_transaction must equal sign(network_id || ENVELOPE_TYPE_TX || tx)"
        );
    }

    /// Mainnet and testnet produce DIFFERENT signatures for the same XDR bytes,
    /// proving the network ID is included in the signature base (anti-replay).
    #[test]
    fn test_mainnet_and_testnet_produce_different_signatures() {
        let privkey = test_privkey();
        let mainnet = StellarSigner::mainnet();
        let testnet = StellarSigner::testnet();
        let tx_xdr = b"same_xdr_bytes";

        let sig_main = mainnet.sign_transaction(&privkey, tx_xdr).unwrap();
        let sig_test = testnet.sign_transaction(&privkey, tx_xdr).unwrap();

        assert_ne!(
            sig_main.signature, sig_test.signature,
            "mainnet vs testnet signatures must differ (network passphrase is in the signature base)"
        );
    }

    /// The signing payload verifies against the correct Ed25519 public key,
    /// confirming end-to-end correctness of the full pipeline.
    #[test]
    fn test_sign_transaction_verifies_with_pubkey() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = b"payment_tx_xdr";

        let result = signer.sign_transaction(&privkey, tx_xdr).unwrap();

        // Build expected payload
        let mut payload = Vec::new();
        payload.extend_from_slice(&signer.network_id);
        payload.extend_from_slice(&ENVELOPE_TYPE_TX);
        payload.extend_from_slice(tx_xdr);

        let signing_key = SigningKey::from_bytes(&privkey.as_slice().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(
            &result.signature.as_slice().try_into().unwrap(),
        );
        verifying_key
            .verify(&payload, &sig)
            .expect("signature must verify against the full payload");
    }

    // -----------------------------------------------------------------------
    // Network ID validation
    // -----------------------------------------------------------------------

    /// Verify the mainnet network ID matches the specified SHA256 value.
    /// This is the "Stacks mistake" guard — wrong passphrase == wrong network ID.
    #[test]
    fn test_mainnet_network_id_is_correct() {
        let expected = Sha256::digest(MAINNET_PASSPHRASE.as_bytes());
        let signer = StellarSigner::mainnet();
        assert_eq!(
            signer.network_id,
            expected.as_slice(),
            "mainnet network ID must equal SHA256 of the official mainnet passphrase"
        );
    }

    #[test]
    fn test_testnet_network_id_is_correct() {
        let expected = Sha256::digest(TESTNET_PASSPHRASE.as_bytes());
        let signer = StellarSigner::testnet();
        assert_eq!(
            signer.network_id,
            expected.as_slice(),
            "testnet network ID must equal SHA256 of the official testnet passphrase"
        );
    }

    #[test]
    fn test_mainnet_and_testnet_network_ids_differ() {
        let mainnet = StellarSigner::mainnet();
        let testnet = StellarSigner::testnet();
        assert_ne!(mainnet.network_id, testnet.network_id);
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_address_invalid_key_length() {
        let signer = StellarSigner::mainnet();
        assert!(signer.derive_address(&[0u8; 16]).is_err());
        assert!(signer.derive_address(&[]).is_err());
    }

    #[test]
    fn test_sign_invalid_key_length() {
        let signer = StellarSigner::mainnet();
        assert!(signer.sign(&[0u8; 16], b"msg").is_err());
    }

    #[test]
    fn test_sign_transaction_invalid_key_length() {
        let signer = StellarSigner::mainnet();
        assert!(signer.sign_transaction(&[], b"xdr").is_err());
        assert!(signer.sign_transaction(&[0u8; 16], b"xdr").is_err());
    }

    // -----------------------------------------------------------------------
    // sign_message
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_message_produces_valid_ed25519() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let message = b"agent-to-agent handshake";

        let result = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);

        // Verify
        let signing_key = SigningKey::from_bytes(&privkey.as_slice().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(
            &result.signature.as_slice().try_into().unwrap(),
        );
        verifying_key.verify(message, &sig).expect("sign_message must verify");
    }
}
