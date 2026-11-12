use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// NEAR Protocol chain signer (Ed25519 over Borsh-serialized transactions).
///
/// # Wire format
///
/// NEAR uses [Borsh](https://borsh.io/) for canonical, deterministic transaction
/// serialization. The signature is computed over `sha256(borsh(Transaction))`
/// and the final `SignedTransaction` is `borsh(Transaction) || borsh(Signature)`,
/// where `Signature` is an enum with discriminant `0x00` (ED25519) followed by
/// the 64-byte signature.
///
/// # Address format
///
/// `derive_address` returns the NEAR **implicit account ID**: the lowercase hex
/// encoding of the 32-byte ed25519 public key (64 chars, no `0x` prefix).
/// Named accounts (e.g. `alice.near`) require on-chain registration and are out
/// of scope for a stateless signer.
///
/// # Network binding
///
/// The signer is genesis-agnostic. Network binding is carried inside the
/// `Transaction.block_hash` field, which callers populate from the target chain
/// via JSON-RPC `block` query.
pub struct NearSigner;

/// Borsh enum discriminant for ED25519 signatures (and public keys) in NEAR.
const KEY_TYPE_ED25519: u8 = 0x00;

pub const NEP413_TAG: u32 = (1 << 31) + 413;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct Nep413Message {
    pub message: String,
    pub nonce: [u8; 32],
    pub recipient: String,
    pub callback_url: Option<String>,
}

impl Nep413Message {
    pub fn signing_preimage(&self) -> Result<Vec<u8>, SignerError> {
        if self.recipient.is_empty() {
            return Err(SignerError::InvalidMessage(
                "NEP-413 recipient must not be empty".into(),
            ));
        }
        let mut out = NEP413_TAG.to_le_bytes().to_vec();
        borsh::to_writer(&mut out, self)
            .map_err(|e| SignerError::InvalidMessage(format!("NEP-413 payload: {e}")))?;
        Ok(out)
    }

    pub fn signing_hash(&self) -> Result<[u8; 32], SignerError> {
        Ok(Sha256::digest(self.signing_preimage()?).into())
    }
}

pub const NEP366_TAG: u32 = (1 << 30) + 366;

const ACTION_DELEGATE: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NearPublicKey {
    Ed25519([u8; 32]),
    Secp256k1([u8; 64]),
}

impl NearPublicKey {
    fn to_json(&self) -> Value {
        match self {
            NearPublicKey::Ed25519(key) => {
                json!(format!("ed25519:{}", bs58::encode(key).into_string()))
            }
            NearPublicKey::Secp256k1(key) => {
                json!(format!("secp256k1:{}", bs58::encode(key).into_string()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AccessKeyPermission {
    FunctionCall {
        allowance: Option<u128>,
        receiver_id: String,
        method_names: Vec<String>,
    },
    FullAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccessKey {
    pub nonce: u64,
    pub permission: AccessKeyPermission,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NonDelegateAction {
    CreateAccount,
    DeployContract {
        code: Vec<u8>,
    },
    FunctionCall {
        method_name: String,
        args: Vec<u8>,
        gas: u64,
        deposit: u128,
    },
    Transfer {
        deposit: u128,
    },
    Stake {
        stake: u128,
        public_key: NearPublicKey,
    },
    AddKey {
        public_key: NearPublicKey,
        access_key: AccessKey,
    },
    DeleteKey {
        public_key: NearPublicKey,
    },
    DeleteAccount {
        beneficiary_id: String,
    },
}

impl NonDelegateAction {
    fn deposit(&self) -> u128 {
        match self {
            NonDelegateAction::FunctionCall { deposit, .. }
            | NonDelegateAction::Transfer { deposit } => *deposit,
            _ => 0,
        }
    }

    fn to_json(&self) -> Value {
        match self {
            NonDelegateAction::CreateAccount => json!({ "type": "create_account" }),
            NonDelegateAction::DeployContract { code } => json!({
                "type": "deploy_contract",
                "code_hash": bs58::encode(Sha256::digest(code)).into_string(),
                "code_len": code.len(),
            }),
            NonDelegateAction::FunctionCall {
                method_name,
                args,
                gas,
                deposit,
            } => json!({
                "type": "function_call",
                "method_name": method_name,
                "args": base64::engine::general_purpose::STANDARD.encode(args),
                "gas": gas.to_string(),
                "deposit": deposit.to_string(),
            }),
            NonDelegateAction::Transfer { deposit } => json!({
                "type": "transfer",
                "deposit": deposit.to_string(),
            }),
            NonDelegateAction::Stake { stake, public_key } => json!({
                "type": "stake",
                "stake": stake.to_string(),
                "public_key": public_key.to_json(),
            }),
            NonDelegateAction::AddKey {
                public_key,
                access_key,
            } => {
                let permission = match &access_key.permission {
                    AccessKeyPermission::FunctionCall {
                        allowance,
                        receiver_id,
                        method_names,
                    } => json!({
                        "type": "function_call",
                        "allowance": allowance.map(|a| a.to_string()),
                        "receiver_id": receiver_id,
                        "method_names": method_names,
                    }),
                    AccessKeyPermission::FullAccess => json!({ "type": "full_access" }),
                };
                json!({
                    "type": "add_key",
                    "public_key": public_key.to_json(),
                    "access_key": {
                        "nonce": access_key.nonce.to_string(),
                        "permission": permission,
                    },
                })
            }
            NonDelegateAction::DeleteKey { public_key } => json!({
                "type": "delete_key",
                "public_key": public_key.to_json(),
            }),
            NonDelegateAction::DeleteAccount { beneficiary_id } => json!({
                "type": "delete_account",
                "beneficiary_id": beneficiary_id,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DelegateAction {
    pub sender_id: String,
    pub receiver_id: String,
    #[borsh(deserialize_with = "deserialize_non_delegate_actions")]
    pub actions: Vec<NonDelegateAction>,
    pub nonce: u64,
    pub max_block_height: u64,
    pub public_key: NearPublicKey,
}

fn deserialize_non_delegate_actions<R: std::io::Read>(
    reader: &mut R,
) -> std::io::Result<Vec<NonDelegateAction>> {
    let len = u32::deserialize_reader(reader)?;
    let mut actions = Vec::new();
    for _ in 0..len {
        let tag = u8::deserialize_reader(reader)?;
        if tag == ACTION_DELEGATE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a delegate action cannot contain another delegate action",
            ));
        }
        actions.push(
            <NonDelegateAction as borsh::BorshDeserialize>::deserialize_reader(
                &mut std::io::Read::chain(&[tag][..], &mut *reader),
            )?,
        );
    }
    Ok(actions)
}

impl DelegateAction {
    pub fn from_borsh(bytes: &[u8]) -> Result<Self, SignerError> {
        borsh::from_slice(bytes)
            .map_err(|e| SignerError::InvalidTransaction(format!("NEP-366 delegate action: {e}")))
    }

    pub fn signing_preimage(bytes: &[u8]) -> Vec<u8> {
        let mut out = NEP366_TAG.to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    pub fn total_deposit(&self) -> Result<u128, SignerError> {
        self.actions.iter().try_fold(0u128, |sum, action| {
            sum.checked_add(action.deposit()).ok_or_else(|| {
                SignerError::InvalidTransaction("NEP-366 total deposit overflows u128".into())
            })
        })
    }

    pub fn to_json(&self) -> Result<Value, SignerError> {
        Ok(json!({
            "kind": "nep366_delegate_action",
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "actions": self.actions.iter().map(NonDelegateAction::to_json).collect::<Vec<_>>(),
            "nonce": self.nonce.to_string(),
            "max_block_height": self.max_block_height.to_string(),
            "public_key": self.public_key.to_json(),
            "total_deposit": self.total_deposit()?.to_string(),
        }))
    }
}

impl NearSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    pub fn sign_nep413_message(
        &self,
        private_key: &[u8],
        message: &Nep413Message,
    ) -> Result<SignOutput, SignerError> {
        let hash = message.signing_hash()?;
        self.sign(private_key, &hash)
    }

    pub fn sign_delegate_action(
        &self,
        private_key: &[u8],
        delegate_action: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let decoded = DelegateAction::from_borsh(delegate_action)?;
        let public_key = Self::signing_key(private_key)?.verifying_key().to_bytes();
        if decoded.public_key != NearPublicKey::Ed25519(public_key) {
            return Err(SignerError::InvalidTransaction(
                "NEP-366 delegate action public_key is not the signing key".into(),
            ));
        }
        let hash = Sha256::digest(DelegateAction::signing_preimage(delegate_action));
        self.sign(private_key, &hash)
    }
}

impl ChainSigner for NearSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Near
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        397
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(hex::encode(verifying_key.as_bytes()))
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(signing_key.verifying_key().as_bytes().to_vec()),
        })
    }

    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
        address: Option<&str>,
    ) -> Result<SignOutput, SignerError> {
        self.verify_sign_message_address(private_key, address)?;
        self.sign(private_key, message)
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // tx_bytes = borsh-serialized NEAR `Transaction`.
        // Signing input is sha256(tx_bytes); ed25519 signs that 32-byte digest.
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        let digest = Sha256::digest(tx_bytes);
        self.sign(private_key, &digest)
    }

    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        // borsh(SignedTransaction) = borsh(Transaction) || borsh(Signature)
        // borsh(Signature::ED25519(sig)) = 0x00 (enum tag) || sig (64 bytes)
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        let mut signed = Vec::with_capacity(tx_bytes.len() + 1 + 64);
        signed.extend_from_slice(tx_bytes);
        signed.push(KEY_TYPE_ED25519);
        signed.extend_from_slice(&signature.signature);
        Ok(signed)
    }

    fn extract_signable_bytes<'a>(&self, tx_bytes: &'a [u8]) -> Result<&'a [u8], SignerError> {
        // NEAR transactions have no envelope; the borsh-serialized Transaction
        // *is* the signable payload. sign_transaction handles the sha256 hashing.
        if tx_bytes.is_empty() {
            return Err(SignerError::InvalidTransaction("empty transaction".into()));
        }
        Ok(tx_bytes)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // NEAR Foundation / Sender Wallet convention: single hardened account index.
        // SLIP-44 coin type 397. Multi-account variation uses different index values.
        format!("m/44'/397'/{}'", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// RFC 8032 test vector 1 — used as a stable seed across the suite.
    const RFC_8032_SEED_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC_8032_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn rfc_seed() -> Vec<u8> {
        hex::decode(RFC_8032_SEED_HEX).unwrap()
    }

    #[test]
    fn test_chain_properties() {
        let signer = NearSigner;
        assert_eq!(signer.chain_type(), ChainType::Near);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 397);
    }

    #[test]
    fn test_derivation_path() {
        let signer = NearSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/397'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/397'/1'");
    }

    #[test]
    fn test_implicit_address_is_lowercase_hex_pubkey() {
        // For RFC 8032 vector 1, the 32-byte pubkey hex IS the implicit
        // NEAR account ID. This is the canonical NEAR rule and the same
        // result `hex(borsh(public_key.data))` produces in near-api-js.
        let signer = NearSigner;
        let address = signer.derive_address(&rfc_seed()).unwrap();
        assert_eq!(address, RFC_8032_PUBKEY_HEX);
        assert_eq!(address.len(), 64);
        assert!(address
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let signer = NearSigner;
        let message = b"test message for near";
        let result = signer.sign(&rfc_seed(), message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert_eq!(result.public_key.as_ref().map(|p| p.len()), Some(32));

        let signing_key = SigningKey::from_bytes(&rfc_seed().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let signer = NearSigner;
        let sig1 = signer.sign(&rfc_seed(), b"hello").unwrap();
        let sig2 = signer.sign(&rfc_seed(), b"hello").unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_message_matches_sign() {
        let signer = NearSigner;
        let msg = b"hello near";
        let s1 = signer.sign(&rfc_seed(), msg).unwrap();
        let s2 = signer.sign_message(&rfc_seed(), msg, None).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_invalid_key_length() {
        let signer = NearSigner;
        assert!(signer.derive_address(&[0u8; 16]).is_err());
        assert!(signer.sign(&[0u8; 33], b"x").is_err());
    }

    #[test]
    fn test_sign_transaction_hashes_with_sha256() {
        // sign_transaction must produce a signature over sha256(tx_bytes),
        // NOT a signature over tx_bytes directly. This is the NEAR convention.
        let signer = NearSigner;
        let tx_bytes = b"borsh-serialized-transaction-placeholder-bytes";

        let signed_tx_output = signer.sign_transaction(&rfc_seed(), tx_bytes).unwrap();
        let signed_raw_output = signer.sign(&rfc_seed(), tx_bytes).unwrap();

        // The two must differ because sign_transaction hashes first.
        assert_ne!(
            signed_tx_output.signature, signed_raw_output.signature,
            "sign_transaction must hash with sha256 before ed25519, not pass-through"
        );

        // Verify the sign_transaction output against sha256(tx_bytes).
        let digest = Sha256::digest(tx_bytes);
        let signing_key = SigningKey::from_bytes(&rfc_seed().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig =
            ed25519_dalek::Signature::from_bytes(&signed_tx_output.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("sign_transaction output must verify against sha256(tx_bytes)");
    }

    #[test]
    fn test_sign_transaction_empty_errors() {
        let signer = NearSigner;
        assert!(signer.sign_transaction(&rfc_seed(), &[]).is_err());
    }

    #[test]
    fn test_extract_signable_bytes_passthrough() {
        let signer = NearSigner;
        let tx_bytes = b"any-borsh-serialized-bytes";
        let extracted = signer.extract_signable_bytes(tx_bytes).unwrap();
        assert_eq!(extracted, tx_bytes);
    }

    #[test]
    fn test_extract_signable_bytes_empty_errors() {
        let signer = NearSigner;
        assert!(signer.extract_signable_bytes(&[]).is_err());
    }

    #[test]
    fn test_encode_signed_transaction_layout() {
        // borsh(SignedTransaction) = tx_bytes || 0x00 (ED25519 tag) || 64-byte sig.
        let signer = NearSigner;
        let tx_bytes = b"FAKE_TX_BORSH";
        let sig = SignOutput {
            signature: vec![0xAB; 64],
            recovery_id: None,
            public_key: None,
        };

        let encoded = signer.encode_signed_transaction(tx_bytes, &sig).unwrap();
        assert_eq!(encoded.len(), tx_bytes.len() + 1 + 64);
        assert_eq!(&encoded[..tx_bytes.len()], tx_bytes);
        assert_eq!(encoded[tx_bytes.len()], KEY_TYPE_ED25519);
        assert_eq!(&encoded[tx_bytes.len() + 1..], &[0xAB; 64]);
    }

    #[test]
    fn test_encode_signed_transaction_rejects_wrong_sig_len() {
        let signer = NearSigner;
        let bad = SignOutput {
            signature: vec![0xAB; 32],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(b"tx", &bad).is_err());
    }

    #[test]
    fn test_encode_signed_transaction_rejects_empty_tx() {
        let signer = NearSigner;
        let sig = SignOutput {
            signature: vec![0xAB; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer.encode_signed_transaction(&[], &sig).is_err());
    }

    /// Byte-parity test against the canonical `near-api-js` reference vector.
    ///
    /// Source: `near/near-api-js`, `test/unit/transactions/data/transaction1.json`.
    /// This is a transfer of 1 yoctoNEAR from `test.near` to `whatever.near`
    /// (nonce=1) signed by ed25519 pubkey
    /// `Anu7LYDfpLtkP7E16LT9imXF694BdQaa9ufVkQiwTQxC` over block_hash
    /// `244ZQ9cgj3CQ6bWBdytfrJMuMQ1jdXLFGnr4HhvtCTnM`.
    ///
    /// Verifies:
    /// 1. `extract_signable_bytes` is a no-op on canonical NEAR borsh tx bytes.
    /// 2. `encode_signed_transaction` emits exactly
    ///    `tx_bytes || 0x00 || sig` (the canonical Borsh layout for
    ///    `SignedTransaction { transaction, signature: Signature::ED25519(_) }`).
    ///
    /// The signature segment itself cannot be byte-matched without the original
    /// private key (which is not part of the public near-api-js fixture); we
    /// verify the wrapping layout instead. Round-trip signing of this exact
    /// `tx_bytes` with our own deterministic ed25519 key is covered by
    /// `test_full_pipeline_extract_sign_encode_roundtrip` below.
    #[test]
    fn test_borsh_byte_parity_with_near_api_js_transaction1() {
        let tx_hex = "09000000746573742e6e65617200917b3d268d4b58f7fec1b150bd68\
                      d69be3ee5d4cc39855e341538465bb77860d01000000000000000d00\
                      00007768617465766572\
                      2e6e6561720fa473fd26901df296be6adc4cc4df34d040efa2435224\
                      b6986910e630c2fef6010000000301000000000000000000000000\
                      000000";
        let tx_bytes = hex::decode(tx_hex).unwrap();

        let signer = NearSigner;

        // (1) extract_signable_bytes is identity for NEAR.
        let signable = signer.extract_signable_bytes(&tx_bytes).unwrap();
        assert_eq!(signable, tx_bytes.as_slice());

        // (2) encode_signed_transaction layout matches near-api-js:
        //     borsh(SignedTransaction) = borsh(Transaction) || 0x00 || sig64
        let dummy_sig = SignOutput {
            signature: vec![0xAB; 64],
            recovery_id: None,
            public_key: None,
        };
        let signed = signer
            .encode_signed_transaction(&tx_bytes, &dummy_sig)
            .unwrap();
        assert_eq!(signed.len(), tx_bytes.len() + 1 + 64);
        assert_eq!(&signed[..tx_bytes.len()], tx_bytes.as_slice());
        assert_eq!(signed[tx_bytes.len()], 0x00, "ED25519 enum discriminant");
        assert_eq!(&signed[tx_bytes.len() + 1..], &[0xAB; 64]);
    }

    struct Nep413Vector {
        message: &'static str,
        nonce_hex: &'static str,
        recipient: &'static str,
        callback_url: Option<&'static str>,
        preimage_hex: &'static str,
        hash_hex: &'static str,
        signature_hex: &'static str,
    }

    const NEP413_VECTORS: &[Nep413Vector] = &[
        Nep413Vector {
            message: "Login request",
            nonce_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            recipient: "example.near",
            callback_url: None,
            preimage_hex: "9d0100800d0000004c6f67696e2072657175657374000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0c0000006578616d706c652e6e65617200",
            hash_hex: "42489eb3ff8180ce947da4a8fc2199a4c3e1a3aeecae967ecdf1db2565ad463f",
            signature_hex: "2320b020f1863ff45a5117fa91ce190e3edab6d000d52d7980822bdf5756457390732bae65729ab62ef33c098407609801fb1cfd5d450a17313bc4885b1c370f",
        },
        Nep413Vector {
            message: "Sign in to example.com",
            nonce_hex: "4242424242424242424242424242424242424242424242424242424242424242",
            recipient: "example.com",
            callback_url: Some("https://example.com/callback"),
            preimage_hex: "9d010080160000005369676e20696e20746f206578616d706c652e636f6d42424242424242424242424242424242424242424242424242424242424242420b0000006578616d706c652e636f6d011c00000068747470733a2f2f6578616d706c652e636f6d2f63616c6c6261636b",
            hash_hex: "73f940eb786541d16f6ddad2977cc10ab9fddee98bcb1f8255dbe5e873b681cb",
            signature_hex: "c76b8fd211f7545b9d3fb863ad38d9bb7fdb31521eea65e13efcf67a48ccbaef0e54c64ae2dd4fd6b8f28dba6463468487ec846e3b1e252588dfbedf0a86a709",
        },
        Nep413Vector {
            message: "h\u{e9}llo \u{2713} \u{4e16}\u{754c}",
            nonce_hex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            recipient: "app.example.near",
            callback_url: Some(""),
            preimage_hex: "9d0100801100000068c3a96c6c6f20e29c9320e4b896e7958cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff100000006170702e6578616d706c652e6e6561720100000000",
            hash_hex: "02709f711f9702f740233322954d854e33c2ed04e52a18d9898f9f54b1d113fa",
            signature_hex: "77b14a2e6dd8543aee54d6f5f6188f2c6c0b7fe0b6a2999c0b02a6c47c4fc1140c48c6910ec65e2350dc9fd0fb543228f9f3472683e30c5eaaf465254acf240c",
        },
        Nep413Vector {
            message: "",
            nonce_hex: "0000000000000000000000000000000000000000000000000000000000000000",
            recipient: "verifier.near",
            callback_url: None,
            preimage_hex: "9d0100800000000000000000000000000000000000000000000000000000000000000000000000000d00000076657269666965722e6e65617200",
            hash_hex: "1003082300749f958b1aa80e496a32b3ce6b4377b52e6ed5782a686aeb59a69a",
            signature_hex: "feda994ffe3a2d87dbffa707a6ec36001a35b0da521470b2560865bf8b2e70dd5262bfcb3505da5ba3212fed34c735ef870f67295d29176eaf48ab2f382f7c02",
        },
    ];

    fn nep413_message(v: &Nep413Vector) -> Nep413Message {
        Nep413Message {
            message: v.message.to_string(),
            nonce: hex::decode(v.nonce_hex).unwrap().try_into().unwrap(),
            recipient: v.recipient.to_string(),
            callback_url: v.callback_url.map(String::from),
        }
    }

    #[test]
    fn test_nep413_matches_near_api_js_vectors() {
        let signer = NearSigner;
        let verifying_key = SigningKey::from_bytes(&rfc_seed().try_into().unwrap()).verifying_key();
        for v in NEP413_VECTORS {
            let msg = nep413_message(v);
            assert_eq!(
                hex::encode(msg.signing_preimage().unwrap()),
                v.preimage_hex,
                "preimage for {:?}",
                v.message
            );
            assert_eq!(hex::encode(msg.signing_hash().unwrap()), v.hash_hex);

            let out = signer.sign_nep413_message(&rfc_seed(), &msg).unwrap();
            assert_eq!(hex::encode(&out.signature), v.signature_hex);
            assert_eq!(
                out.public_key.as_deref(),
                Some(verifying_key.as_bytes().as_slice())
            );
            let sig = ed25519_dalek::Signature::from_bytes(&out.signature.try_into().unwrap());
            verifying_key
                .verify(&msg.signing_hash().unwrap(), &sig)
                .expect("NEP-413 signature must verify against the payload hash");
        }
    }

    #[test]
    fn test_nep413_rejects_empty_recipient() {
        let signer = NearSigner;
        let mut msg = nep413_message(&NEP413_VECTORS[0]);
        msg.recipient = String::new();
        assert!(matches!(
            msg.signing_preimage(),
            Err(SignerError::InvalidMessage(_))
        ));
        assert!(signer.sign_nep413_message(&rfc_seed(), &msg).is_err());
    }

    #[test]
    fn test_nep413_rejects_invalid_key() {
        let signer = NearSigner;
        let msg = nep413_message(&NEP413_VECTORS[0]);
        assert!(signer.sign_nep413_message(&[0u8; 31], &msg).is_err());
    }

    #[test]
    fn test_full_pipeline_extract_sign_encode_roundtrip() {
        let signer = NearSigner;
        let tx_bytes = b"a-realistic-looking-borsh-transaction-payload";

        // Pipeline mirrors how ops.rs invokes the signer:
        //   extract -> sign_transaction -> encode_signed_transaction
        let signable = signer.extract_signable_bytes(tx_bytes).unwrap();
        assert_eq!(signable, tx_bytes);

        let output = signer.sign_transaction(&rfc_seed(), signable).unwrap();
        let encoded = signer.encode_signed_transaction(tx_bytes, &output).unwrap();

        // The encoded SignedTransaction must contain the original tx unchanged.
        assert_eq!(&encoded[..tx_bytes.len()], tx_bytes);
        // Followed by the ED25519 tag.
        assert_eq!(encoded[tx_bytes.len()], KEY_TYPE_ED25519);
        // Followed by the 64-byte signature.
        assert_eq!(&encoded[tx_bytes.len() + 1..], output.signature.as_slice());

        // And the signature must verify against sha256(tx_bytes).
        let digest = Sha256::digest(tx_bytes);
        let signing_key = SigningKey::from_bytes(&rfc_seed().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig =
            ed25519_dalek::Signature::from_bytes(&output.signature.clone().try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("signature must verify against sha256(tx_bytes)");
    }

    struct DelegateVector {
        delegate_action_hex: &'static str,
        signature_hex: &'static str,
        expected: &'static str,
    }

    const DELEGATE_VECTORS: &[DelegateVector] = &[
        DelegateVector {
            delegate_action_hex: "40000000643735613938303138326231306162376435346266656433633936343037336130656531373266336461613632333235616630323161363866373037353131610f00000066742e6578616d706c652e6e65617201000000020b00000066745f7472616e736665723a0000007b2272656365697665725f6964223a226d65726368616e742e6578616d706c652e6e656172222c22616d6f756e74223a2231303030303030227d00e057eb481b0000010000000000000000000000000000002a0000000000000000e1f5050000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            signature_hex: "b01b4df30474223b0892e3bc1fe7b8fb9362b8783e89017be2e9a4bbc88d9c9054e6f33067c97fc2de71602b54844990cc72c382a23b1a5e0a1390b9b72c4200",
            expected: r#"{"kind":"nep366_delegate_action","sender_id":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","receiver_id":"ft.example.near","actions":[{"type":"function_call","method_name":"ft_transfer","args":"eyJyZWNlaXZlcl9pZCI6Im1lcmNoYW50LmV4YW1wbGUubmVhciIsImFtb3VudCI6IjEwMDAwMDAifQ==","gas":"30000000000000","deposit":"1"}],"nonce":"42","max_block_height":"100000000","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","total_deposit":"1"}"#,
        },
        DelegateVector {
            delegate_action_hex: "120000006167656e742e6578616d706c652e6e65617213000000657363726f772e6578616d706c652e6e6561720300000003000000a1edccce1bc2d3000000000000021000000066745f7472616e736665725f63616c6c3b0000007b2272656365697665725f6964223a22657363726f772e6578616d706c652e6e656172222c22616d6f756e74223a2235222c226d7367223a22227d00203d88792d0000010000000000000000000000000000000500070707070707070707070707070707070707070707070707070707070707070700000000000000000001000040683bb3f386f03400000000000013000000657363726f772e6578616d706c652e6e6561720200000005000000636c61696d06000000726566756e64ffffffffffffffff010000000000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            signature_hex: "aa2272bbd8b8169ddeccf62735c11f69e87c66d14ad30702c9cf4692c793a2cb29fe8e9d8557847ccc2296eb1ce5827e67162b0eba997ceefb62fd53c0025f0b",
            expected: r#"{"kind":"nep366_delegate_action","sender_id":"agent.example.near","receiver_id":"escrow.example.near","actions":[{"type":"transfer","deposit":"1000000000000000000000000"},{"type":"function_call","method_name":"ft_transfer_call","args":"eyJyZWNlaXZlcl9pZCI6ImVzY3Jvdy5leGFtcGxlLm5lYXIiLCJhbW91bnQiOiI1IiwibXNnIjoiIn0=","gas":"50000000000000","deposit":"1"},{"type":"add_key","public_key":"ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx","access_key":{"nonce":"0","permission":{"type":"function_call","allowance":"250000000000000000000000","receiver_id":"escrow.example.near","method_names":["claim","refund"]}}}],"nonce":"18446744073709551615","max_block_height":"1","public_key":"ed25519:FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z","total_deposit":"1000000000000000000000001"}"#,
        },
    ];

    #[test]
    fn test_nep366_tag_bytes() {
        assert_eq!(NEP366_TAG.to_le_bytes(), [0x6e, 0x01, 0x00, 0x40]);
    }

    #[test]
    fn test_delegate_actions_match_near_api_js() {
        for v in DELEGATE_VECTORS {
            let bytes = hex::decode(v.delegate_action_hex).unwrap();
            let decoded = DelegateAction::from_borsh(&bytes).unwrap();
            let expected: Value = serde_json::from_str(v.expected).unwrap();
            assert_eq!(decoded.to_json().unwrap(), expected);
            assert_eq!(borsh::to_vec(&decoded).unwrap(), bytes);

            let out = NearSigner
                .sign_delegate_action(&rfc_seed(), &bytes)
                .unwrap();
            assert_eq!(hex::encode(&out.signature), v.signature_hex);
        }
    }

    #[test]
    fn test_delegate_action_requires_the_signing_key() {
        let bytes = hex::decode(DELEGATE_VECTORS[0].delegate_action_hex).unwrap();
        let err = NearSigner
            .sign_delegate_action(&[0x01; 32], &bytes)
            .unwrap_err();
        assert!(err.to_string().contains("is not the signing key"), "{err}");

        let mut decoded = DelegateAction::from_borsh(&bytes).unwrap();
        decoded.public_key = NearPublicKey::Secp256k1([0x02; 64]);
        let secp = borsh::to_vec(&decoded).unwrap();
        assert!(DelegateAction::from_borsh(&secp).is_ok());
        assert!(NearSigner.sign_delegate_action(&rfc_seed(), &secp).is_err());
        assert!(NearSigner
            .sign_delegate_action(&[0x01; 31], &bytes)
            .is_err());
    }

    #[test]
    fn test_delegate_action_rejects_malformed_input() {
        let bytes = hex::decode(DELEGATE_VECTORS[0].delegate_action_hex).unwrap();
        let prefixed = DelegateAction::signing_preimage(&bytes);
        assert!(NearSigner
            .sign_delegate_action(&rfc_seed(), &prefixed)
            .is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DelegateAction::from_borsh(&trailing).is_err());
        assert!(DelegateAction::from_borsh(&bytes[..bytes.len() - 1]).is_err());
        assert!(DelegateAction::from_borsh(&[]).is_err());
    }

    #[test]
    fn test_delegate_action_rejects_nested_delegate() {
        let outer = DelegateAction {
            sender_id: "a.near".into(),
            receiver_id: "b.near".into(),
            actions: vec![],
            nonce: 1,
            max_block_height: 1,
            public_key: NearPublicKey::Ed25519([0; 32]),
        };
        let mut bytes = borsh::to_vec(&outer.sender_id).unwrap();
        bytes.extend(borsh::to_vec(&outer.receiver_id).unwrap());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(ACTION_DELEGATE);
        bytes.extend(borsh::to_vec(&outer).unwrap());
        bytes.push(0);
        bytes.extend([0u8; 64]);
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(1u64.to_le_bytes());
        bytes.extend(borsh::to_vec(&outer.public_key).unwrap());
        let err = DelegateAction::from_borsh(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("cannot contain another delegate"),
            "{err}"
        );
    }

    #[test]
    fn test_delegate_action_total_deposit_overflow_is_an_error() {
        let delegate = DelegateAction {
            sender_id: "a.near".into(),
            receiver_id: "b.near".into(),
            actions: vec![
                NonDelegateAction::Transfer { deposit: u128::MAX },
                NonDelegateAction::Transfer { deposit: 1 },
            ],
            nonce: 1,
            max_block_height: 1,
            public_key: NearPublicKey::Ed25519([0; 32]),
        };
        assert!(delegate.to_json().is_err());
    }
}
