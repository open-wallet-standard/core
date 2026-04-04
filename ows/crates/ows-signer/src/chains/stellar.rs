use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    BytesM, DecoratedSignature, Limits, MuxedAccount, ReadXdr, Signature, SignatureHint,
    Transaction as StellarTransaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

/// Mainnet network passphrase.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
/// Testnet network passphrase.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

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
/// Stellar signs the canonical XDR encoding of `TransactionSignaturePayload`.
/// This includes the network ID and the envelope type, so mainnet and testnet
/// signatures differ for the same transaction envelope.
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
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    fn parse_transaction_envelope(tx_xdr_bytes: &[u8]) -> Result<TransactionEnvelope, SignerError> {
        TransactionEnvelope::from_xdr(tx_xdr_bytes, Limits::none()).map_err(|e| {
            SignerError::InvalidTransaction(format!(
                "invalid Stellar transaction envelope XDR: {e}"
            ))
        })
    }

    fn v0_transaction_to_v1(tx: &stellar_xdr::curr::TransactionV0) -> StellarTransaction {
        StellarTransaction {
            source_account: MuxedAccount::Ed25519(tx.source_account_ed25519.clone()),
            fee: tx.fee,
            seq_num: tx.seq_num.clone(),
            cond: match tx.time_bounds.clone() {
                Some(bounds) => stellar_xdr::curr::Preconditions::Time(bounds),
                None => stellar_xdr::curr::Preconditions::None,
            },
            memo: tx.memo.clone(),
            operations: tx.operations.clone(),
            ext: TransactionExt::V0,
        }
    }

    fn transaction_signature_payload(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<Vec<u8>, SignerError> {
        let tagged_transaction = match envelope {
            TransactionEnvelope::TxV0(env) => TransactionSignaturePayloadTaggedTransaction::Tx(
                Self::v0_transaction_to_v1(&env.tx),
            ),
            TransactionEnvelope::Tx(env) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(env.tx.clone())
            }
            TransactionEnvelope::TxFeeBump(env) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(env.tx.clone())
            }
        };

        TransactionSignaturePayload {
            network_id: self.network_id.into(),
            tagged_transaction,
        }
        .to_xdr(Limits::none())
        .map_err(|e| {
            SignerError::InvalidTransaction(format!(
                "failed to encode Stellar transaction signature payload: {e}"
            ))
        })
    }

    fn transaction_signature_digest(
        &self,
        envelope: &TransactionEnvelope,
    ) -> Result<[u8; 32], SignerError> {
        let payload = self.transaction_signature_payload(envelope)?;
        Ok(Sha256::digest(payload).into())
    }

    fn verifying_key_bytes(private_key: &[u8]) -> Result<[u8; 32], SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        Ok(*signing_key.verifying_key().as_bytes())
    }

    fn decorated_signature(signature: &SignOutput) -> Result<DecoratedSignature, SignerError> {
        let public_key = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction(
                "stellar signed transaction encoding requires the signer's public key".into(),
            )
        })?;
        let pubkey_bytes: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            SignerError::InvalidTransaction(format!(
                "stellar signer public key must be 32 bytes, got {}",
                public_key.len()
            ))
        })?;
        let sig_bytes: BytesM<64> = signature.signature.clone().try_into().map_err(|_| {
            SignerError::InvalidTransaction("stellar signature must be 64 bytes".into())
        })?;

        Ok(DecoratedSignature {
            hint: SignatureHint(pubkey_bytes[28..32].try_into().unwrap()),
            signature: Signature(sig_bytes),
        })
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
        payload.push((crc >> 8) as u8); // high byte second

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

    /// Sign a Stellar `TransactionEnvelope` XDR blob.
    ///
    /// The input must be unsigned envelope XDR, not arbitrary bytes. The signer
    /// parses the envelope, constructs the canonical `TransactionSignaturePayload`,
    /// hashes it with SHA-256, then signs the 32-byte digest with Ed25519.
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
        let envelope = Self::parse_transaction_envelope(tx_xdr_bytes)?;
        let signing_key = Self::signing_key(private_key)?;
        let digest = self.transaction_signature_digest(&envelope)?;
        let signature = signing_key.sign(&digest);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(Self::verifying_key_bytes(private_key)?.to_vec()),
        })
    }

    fn encode_signed_transaction(
        &self,
        tx_xdr_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        let decorated = Self::decorated_signature(signature)?;
        let envelope = Self::parse_transaction_envelope(tx_xdr_bytes)?;

        let signed_envelope = match envelope {
            TransactionEnvelope::TxV0(mut env) => {
                let mut signatures: Vec<_> = env.signatures.into();
                signatures.push(decorated);
                env.signatures = signatures.try_into().map_err(|e| {
                    SignerError::InvalidTransaction(format!(
                        "failed to append Stellar signature to tx_v0 envelope: {e}"
                    ))
                })?;
                TransactionEnvelope::TxV0(env)
            }
            TransactionEnvelope::Tx(mut env) => {
                let mut signatures: Vec<_> = env.signatures.into();
                signatures.push(decorated);
                env.signatures = signatures.try_into().map_err(|e| {
                    SignerError::InvalidTransaction(format!(
                        "failed to append Stellar signature to tx envelope: {e}"
                    ))
                })?;
                TransactionEnvelope::Tx(env)
            }
            TransactionEnvelope::TxFeeBump(mut env) => {
                let mut signatures: Vec<_> = env.signatures.into();
                signatures.push(decorated);
                env.signatures = signatures.try_into().map_err(|e| {
                    SignerError::InvalidTransaction(format!(
                        "failed to append Stellar signature to fee bump envelope: {e}"
                    ))
                })?;
                TransactionEnvelope::TxFeeBump(env)
            }
        };

        signed_envelope.to_xdr(Limits::none()).map_err(|e| {
            SignerError::InvalidTransaction(format!(
                "failed to encode signed Stellar transaction envelope: {e}"
            ))
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
    let mut output = String::with_capacity((data.len() * 8).div_ceil(5));
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
    use stellar_xdr::curr::{
        Limits, Memo, Preconditions, Transaction as StellarTransaction, TransactionEnvelope,
        TransactionExt, TransactionV1Envelope, Uint256,
    };

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
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

    fn test_pubkey() -> [u8; 32] {
        StellarSigner::verifying_key_bytes(&test_privkey()).unwrap()
    }

    fn unsigned_test_envelope_xdr() -> Vec<u8> {
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: StellarTransaction {
                source_account: MuxedAccount::Ed25519(Uint256::from(test_pubkey())),
                fee: 100,
                seq_num: 1_i64.into(),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: Vec::<stellar_xdr::curr::Operation>::new()
                    .try_into()
                    .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: Vec::<DecoratedSignature>::new().try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
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
            address
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
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
                &mnemonic,
                "",
                &signer.default_derivation_path(0),
                Curve::Ed25519,
            )
            .unwrap();
            signer.derive_address(key.expose()).unwrap()
        };
        let addr1 = {
            let key = HdDeriver::derive_from_mnemonic(
                &mnemonic,
                "",
                &signer.default_derivation_path(1),
                Curve::Ed25519,
            )
            .unwrap();
            signer.derive_address(key.expose()).unwrap()
        };
        assert_ne!(
            addr0, addr1,
            "different indices must produce different addresses"
        );
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
        let sig =
            ed25519_dalek::Signature::from_bytes(&result.signature.as_slice().try_into().unwrap());
        verifying_key
            .verify(message, &sig)
            .expect("signature must verify");
    }

    // -----------------------------------------------------------------------
    // sign_transaction (Stellar signature base)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_transaction_produces_64_byte_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = unsigned_test_envelope_xdr();
        let result = signer.sign_transaction(&privkey, &tx_xdr).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert_eq!(result.public_key.as_deref(), Some(&test_pubkey()[..]));
    }

    #[test]
    fn test_sign_transaction_is_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = unsigned_test_envelope_xdr();
        let sig1 = signer.sign_transaction(&privkey, &tx_xdr).unwrap();
        let sig2 = signer.sign_transaction(&privkey, &tx_xdr).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_transaction_empty_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        assert!(signer.sign_transaction(&privkey, b"").is_err());
    }

    #[test]
    fn test_sign_transaction_rejects_arbitrary_bytes() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        assert!(signer
            .sign_transaction(&privkey, b"fake_xdr_transaction_bytes")
            .is_err());
    }

    /// Core interop validity check: sign_transaction(tx) must equal
    /// sign(SHA256(network_id || ENVELOPE_TYPE_TX || tx)), proving the
    /// signature base is constructed correctly.
    #[test]
    fn test_sign_transaction_equals_sign_of_signature_payload_digest() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = unsigned_test_envelope_xdr();
        let envelope = StellarSigner::parse_transaction_envelope(&tx_xdr).unwrap();

        let sig_tx = signer.sign_transaction(&privkey, &tx_xdr).unwrap();

        let digest = signer.transaction_signature_digest(&envelope).unwrap();
        let sig_direct = signer.sign(&privkey, &digest).unwrap();

        assert_eq!(
            sig_tx.signature, sig_direct.signature,
            "sign_transaction must equal signing the SHA256 of the canonical TransactionSignaturePayload XDR"
        );
    }

    /// Mainnet and testnet produce DIFFERENT signatures for the same XDR bytes,
    /// proving the network ID is included in the signature base (anti-replay).
    #[test]
    fn test_mainnet_and_testnet_produce_different_signatures() {
        let privkey = test_privkey();
        let mainnet = StellarSigner::mainnet();
        let testnet = StellarSigner::testnet();
        let tx_xdr = unsigned_test_envelope_xdr();

        let sig_main = mainnet.sign_transaction(&privkey, &tx_xdr).unwrap();
        let sig_test = testnet.sign_transaction(&privkey, &tx_xdr).unwrap();

        assert_ne!(
            sig_main.signature, sig_test.signature,
            "mainnet vs testnet signatures must differ (network passphrase is in the signature base)"
        );
    }

    /// The signing payload digest verifies against the correct Ed25519 public
    /// key, confirming end-to-end correctness of the full pipeline.
    #[test]
    fn test_sign_transaction_verifies_payload_digest_with_pubkey() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = unsigned_test_envelope_xdr();
        let envelope = StellarSigner::parse_transaction_envelope(&tx_xdr).unwrap();

        let result = signer.sign_transaction(&privkey, &tx_xdr).unwrap();

        let digest = signer.transaction_signature_digest(&envelope).unwrap();

        let signing_key = SigningKey::from_bytes(&privkey.as_slice().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig =
            ed25519_dalek::Signature::from_bytes(&result.signature.as_slice().try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("signature must verify against the payload digest");
    }

    #[test]
    fn test_encode_signed_transaction_appends_decorated_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::mainnet();
        let tx_xdr = unsigned_test_envelope_xdr();

        let signed = signer
            .encode_signed_transaction(
                &tx_xdr,
                &signer.sign_transaction(&privkey, &tx_xdr).unwrap(),
            )
            .unwrap();
        let envelope = TransactionEnvelope::from_xdr(&signed, Limits::none()).unwrap();

        match envelope {
            TransactionEnvelope::Tx(env) => {
                assert_eq!(env.signatures.len(), 1);
                let expected_hint: [u8; 4] = test_pubkey()[28..32].try_into().unwrap();
                assert_eq!(env.signatures[0].hint.0, expected_hint);
                assert_eq!(env.signatures[0].signature.0.len(), 64);
            }
            other => panic!("expected tx envelope, got {:?}", other.name()),
        }
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
        let tx_xdr = unsigned_test_envelope_xdr();
        assert!(signer.sign_transaction(&[], &tx_xdr).is_err());
        assert!(signer.sign_transaction(&[0u8; 16], &tx_xdr).is_err());
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
        let sig =
            ed25519_dalek::Signature::from_bytes(&result.signature.as_slice().try_into().unwrap());
        verifying_key
            .verify(message, &sig)
            .expect("sign_message must verify");
    }
}
