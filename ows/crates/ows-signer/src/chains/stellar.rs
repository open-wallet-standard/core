use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::{
    ChainType, STELLAR_PASSPHRASE_FUTURENET, STELLAR_PASSPHRASE_PUBNET,
    STELLAR_PASSPHRASE_TESTNET,
};
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    DecoratedSignature, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

/// Stellar chain signer (Ed25519).
///
/// Stateful struct storing the network passphrase, which is required for
/// building the `TransactionSignaturePayload` during transaction signing.
/// Follows the same pattern as `BitcoinSigner` (HRP) and `CosmosSigner` (HRP).
pub struct StellarSigner {
    network_passphrase: &'static str,
}

impl StellarSigner {
    pub fn pubnet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_PUBNET,
        }
    }

    pub fn testnet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_TESTNET,
        }
    }

    pub fn futurenet() -> Self {
        StellarSigner {
            network_passphrase: STELLAR_PASSPHRASE_FUTURENET,
        }
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for StellarSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stellar
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        148
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/148'/{}'", index)
    }

    /// Derive a Stellar `G...` address from a private key.
    ///
    /// Uses Strkey encoding: `base32(versionByte + ed25519PublicKey + CRC16)`.
    /// Version byte 48 (6 << 3) produces the `G` prefix.
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let strkey =
            stellar_strkey::ed25519::PublicKey(*verifying_key.as_bytes());
        Ok(String::from(strkey.to_string().as_str()))
    }

    /// Sign raw bytes with Ed25519 (no prefixing, no hashing).
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Sign a Stellar transaction envelope (XDR bytes).
    ///
    /// 1. Parse the `TransactionEnvelope` from XDR
    /// 2. Extract the transaction body
    /// 3. Build `TransactionSignaturePayload` with `SHA256(network_passphrase)` as networkId
    /// 4. Serialize the payload to XDR, SHA-256 hash it
    /// 5. Ed25519 sign the hash
    /// 6. Return signature + public key (needed for DecoratedSignature hint)
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

        let signing_key = Self::signing_key(private_key)?;

        // Parse the envelope to extract the transaction body
        let envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR parse failed: {e}")))?;

        // Build the tagged transaction for the signature payload
        let tagged_tx = match &envelope {
            TransactionEnvelope::TxV0(v0) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(
                    // V0 envelopes contain a TransactionV0; we need to
                    // convert to a Transaction for the payload. However,
                    // stellar-xdr doesn't provide a direct conversion.
                    // For V0, we build the payload using the Tx variant
                    // after converting the V0 inner transaction.
                    //
                    // Actually, stellar-xdr has TxV0 variant in the payload tagged transaction:
                    // Let's check... No, the XDR spec says the signature payload uses
                    // ENVELOPE_TYPE_TX or ENVELOPE_TYPE_TX_FEE_BUMP.
                    // For V0 envelopes, we still use ENVELOPE_TYPE_TX with the tx body.
                    // The stellar SDK converts V0 to V1 for signing purposes.
                    // We'll handle this by reading the V0 tx fields directly.
                    {
                        // Convert V0 to a Transaction struct for signing.
                        // V0 transactions have the source as an ed25519 key (32 bytes)
                        // while V1 uses a MuxedAccount. The signing payload should
                        // use the Transaction (V1) form.
                        use stellar_xdr::curr::{MuxedAccount, Transaction, Uint256};
                        Transaction {
                            source_account: MuxedAccount::Ed25519(Uint256(
                                v0.tx.source_account_ed25519.0,
                            )),
                            fee: v0.tx.fee,
                            seq_num: v0.tx.seq_num.clone(),
                            cond: match &v0.tx.time_bounds {
                                Some(tb) => stellar_xdr::curr::Preconditions::Time(tb.clone()),
                                None => stellar_xdr::curr::Preconditions::None,
                            },
                            memo: v0.tx.memo.clone(),
                            operations: v0.tx.operations.clone(),
                            ext: stellar_xdr::curr::TransactionExt::V0,
                        }
                    },
                )
            }
            TransactionEnvelope::Tx(v1) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
            }
            TransactionEnvelope::TxFeeBump(fb) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(fb.tx.clone())
            }
        };

        // Compute networkId = SHA256(passphrase)
        let network_id: [u8; 32] = Sha256::digest(self.network_passphrase.as_bytes()).into();

        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };

        // Serialize payload to XDR, then SHA-256 hash it
        let payload_xdr = payload
            .to_xdr(Limits::none())
            .map_err(|e| SignerError::SigningFailed(format!("XDR serialize failed: {e}")))?;
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        // Ed25519 sign the hash
        let signature = signing_key.sign(&hash);
        let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes),
        })
    }

    /// Encode a signed Stellar transaction: append a DecoratedSignature to the envelope.
    ///
    /// The `SignOutput` must contain `public_key` (32 bytes) for the signature hint
    /// (last 4 bytes of the public key).
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }

        let pubkey_bytes = signature
            .public_key
            .as_ref()
            .ok_or_else(|| {
                SignerError::InvalidTransaction(
                    "public_key required for Stellar DecoratedSignature hint".into(),
                )
            })?;

        if pubkey_bytes.len() != 32 {
            return Err(SignerError::InvalidTransaction(format!(
                "expected 32-byte public key, got {}",
                pubkey_bytes.len()
            )));
        }

        let mut envelope = TransactionEnvelope::from_xdr(tx_bytes, Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR parse failed: {e}")))?;

        // Build the DecoratedSignature: hint (last 4 bytes of pubkey) + 64-byte sig
        let hint = SignatureHint([
            pubkey_bytes[28],
            pubkey_bytes[29],
            pubkey_bytes[30],
            pubkey_bytes[31],
        ]);

        let sig_bytes: [u8; 64] = signature.signature[..64]
            .try_into()
            .map_err(|_| SignerError::InvalidTransaction("signature must be 64 bytes".into()))?;

        let decorated = DecoratedSignature {
            hint,
            signature: Signature(sig_bytes.try_into().map_err(|_| {
                SignerError::InvalidTransaction("failed to create Signature".into())
            })?),
        };

        // Append to the envelope's signatures array.
        // VecM doesn't support push directly; convert to Vec, push, convert back.
        fn append_sig(
            sigs: &stellar_xdr::curr::VecM<DecoratedSignature, 20>,
            sig: DecoratedSignature,
        ) -> Result<stellar_xdr::curr::VecM<DecoratedSignature, 20>, SignerError> {
            let mut v = sigs.to_vec();
            v.push(sig);
            v.try_into().map_err(|_| {
                SignerError::InvalidTransaction("too many signatures (max 20)".into())
            })
        }

        match &mut envelope {
            TransactionEnvelope::TxV0(ref mut v0) => {
                v0.signatures = append_sig(&v0.signatures, decorated)?;
            }
            TransactionEnvelope::Tx(ref mut v1) => {
                v1.signatures = append_sig(&v1.signatures, decorated)?;
            }
            TransactionEnvelope::TxFeeBump(ref mut fb) => {
                fb.signatures = append_sig(&fb.signatures, decorated)?;
            }
        }

        // Re-serialize to XDR
        envelope
            .to_xdr(Limits::none())
            .map_err(|e| SignerError::InvalidTransaction(format!("XDR serialize failed: {e}")))
    }

    /// Sign a message using SEP-53: `SHA256("Stellar Signed Message:\n" + message)`.
    fn sign_message(
        &self,
        private_key: &[u8],
        message: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;

        // SEP-53 payload: prefix + message
        let mut payload = Vec::with_capacity(24 + message.len());
        payload.extend_from_slice(b"Stellar Signed Message:\n");
        payload.extend_from_slice(message);

        let hash: [u8; 32] = Sha256::digest(&payload).into();
        let signature = signing_key.sign(&hash);
        let pubkey_bytes = signing_key.verifying_key().to_bytes().to_vec();

        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(pubkey_bytes),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hd::HdDeriver;
    use crate::mnemonic::Mnemonic;
    use ed25519_dalek::Verifier;

    const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_privkey() -> Vec<u8> {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::pubnet();
        let path = signer.default_derivation_path(0);
        HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519)
            .unwrap()
            .expose()
            .to_vec()
    }

    #[test]
    fn test_chain_properties() {
        let signer = StellarSigner::pubnet();
        assert_eq!(signer.chain_type(), ChainType::Stellar);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 148);
    }

    #[test]
    fn test_derivation_path() {
        let signer = StellarSigner::pubnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'");
        assert_eq!(signer.default_derivation_path(1), "m/44'/148'/1'");
        assert_eq!(signer.default_derivation_path(5), "m/44'/148'/5'");
    }

    #[test]
    fn test_derive_address_format() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let address = signer.derive_address(&privkey).unwrap();

        assert!(
            address.starts_with('G'),
            "Stellar address must start with 'G', got: {}",
            address
        );
        assert_eq!(
            address.len(),
            56,
            "Stellar address must be 56 chars, got: {}",
            address.len()
        );
        // Second character must be A, B, C, or D
        let second = address.chars().nth(1).unwrap();
        assert!(
            "ABCD".contains(second),
            "Second char must be A/B/C/D, got: {}",
            second
        );
    }

    /// SEP-0005 known vector: "abandon..." mnemonic at m/44'/148'/0'
    /// produces address GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX
    #[test]
    fn test_derive_address_known_vector_sep0005() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let address = signer.derive_address(&privkey).unwrap();
        assert_eq!(
            address, "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX"
        );
    }

    #[test]
    fn test_derive_address_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let addr1 = signer.derive_address(&privkey).unwrap();
        let addr2 = signer.derive_address(&privkey).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_derive_address_invalid_key() {
        let signer = StellarSigner::pubnet();
        assert!(signer.derive_address(&[0u8; 16]).is_err());
        assert!(signer.derive_address(&[]).is_err());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();

        let message = b"test message for stellar";
        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());

        // Verify
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).expect("should verify");
    }

    #[test]
    fn test_deterministic_signature() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let message = b"hello";

        let sig1 = signer.sign(&privkey, message).unwrap();
        let sig2 = signer.sign(&privkey, message).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_extract_signable_bytes_passthrough() {
        let signer = StellarSigner::pubnet();
        let data = b"some envelope bytes";
        let result = signer.extract_signable_bytes(data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_sign_transaction_empty_input_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        assert!(signer.sign_transaction(&privkey, b"").is_err());
    }

    #[test]
    fn test_sign_transaction_invalid_xdr_errors() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        assert!(signer.sign_transaction(&privkey, b"not valid xdr").is_err());
    }

    #[test]
    fn test_sign_transaction_invalid_privkey() {
        let signer = StellarSigner::testnet();
        // Need valid XDR for this test — we'll just verify invalid key is caught
        assert!(signer.sign_transaction(&[], b"some bytes").is_err());
        assert!(signer.sign_transaction(&[0u8; 16], b"some bytes").is_err());
    }

    /// Build a minimal valid V1 TransactionEnvelope XDR for testing.
    // NOTE: duplicated in crates/ows-lib/src/ops.rs (mnemonic_wallet_sign_tx_all_chains) — keep in sync
    fn build_test_envelope() -> Vec<u8> {
        use stellar_xdr::curr::*;

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0xAA; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        };

        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn test_sign_transaction_produces_64_byte_sig() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert!(result.public_key.is_some());
        assert_eq!(result.public_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_sign_transaction_deterministic() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let sig1 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let sig2 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(sig1.signature, sig2.signature);
    }

    #[test]
    fn test_sign_transaction_equivalence() {
        // Verify that sign_transaction produces the same result as manually building
        // the TransactionSignaturePayload, SHA-256 hashing, and ed25519 signing.
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();

        // Manually compute the expected signature
        let envelope =
            TransactionEnvelope::from_xdr(&envelope_xdr, Limits::none()).unwrap();
        let tagged_tx = match &envelope {
            TransactionEnvelope::Tx(v1) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone())
            }
            _ => panic!("expected V1 envelope"),
        };

        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let expected_sig = signing_key.sign(&hash);

        assert_eq!(
            result.signature,
            expected_sig.to_bytes().to_vec(),
            "sign_transaction must match manual TransactionSignaturePayload signing"
        );
    }

    #[test]
    fn test_encode_signed_transaction_roundtrip() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let sign_output = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let signed = signer
            .encode_signed_transaction(&envelope_xdr, &sign_output)
            .unwrap();

        // Deserialize and verify
        let signed_envelope =
            TransactionEnvelope::from_xdr(&signed, Limits::none()).unwrap();
        match signed_envelope {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 1);
                let dec_sig = &v1.signatures[0];
                // Hint = last 4 bytes of pubkey
                let pubkey = sign_output.public_key.as_ref().unwrap();
                assert_eq!(dec_sig.hint.0, pubkey[28..32]);
                assert_eq!(dec_sig.signature.0.as_slice(), &sign_output.signature[..]);
            }
            _ => panic!("expected V1 envelope"),
        }
    }

    #[test]
    fn test_encode_signed_transaction_multi_sig() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        // First signature
        let sig1 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let once_signed = signer
            .encode_signed_transaction(&envelope_xdr, &sig1)
            .unwrap();

        // Second signature (same key, but tests multi-sig append)
        let sig2 = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        let twice_signed = signer
            .encode_signed_transaction(&once_signed, &sig2)
            .unwrap();

        let env = TransactionEnvelope::from_xdr(&twice_signed, Limits::none()).unwrap();
        match env {
            TransactionEnvelope::Tx(v1) => {
                assert_eq!(v1.signatures.len(), 2, "should have 2 signatures");
            }
            _ => panic!("expected V1 envelope"),
        }
    }

    #[test]
    fn test_encode_signed_transaction_missing_pubkey_errors() {
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let bad_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: None,
        };
        assert!(signer
            .encode_signed_transaction(&envelope_xdr, &bad_output)
            .is_err());
    }

    #[test]
    fn test_full_pipeline() {
        // extract → sign → encode → verify
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_envelope();

        let signable = signer.extract_signable_bytes(&envelope_xdr).unwrap();
        assert_eq!(signable, &envelope_xdr[..]); // passthrough

        let output = signer.sign_transaction(&privkey, signable).unwrap();
        let signed = signer
            .encode_signed_transaction(&envelope_xdr, &output)
            .unwrap();

        // Verify signed envelope is valid XDR with 1 signature
        let env = TransactionEnvelope::from_xdr(&signed, Limits::none()).unwrap();
        match env {
            TransactionEnvelope::Tx(v1) => assert_eq!(v1.signatures.len(), 1),
            _ => panic!("expected V1 envelope"),
        }
    }

    /// SEP-53 message signing test vector.
    /// Seed: SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW
    /// Address: GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L
    /// Message: "Hello, World!"
    /// Signature (base64): fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==
    #[test]
    fn test_sign_message_sep53_test_vector() {
        // Decode the secret key from Stellar secret format (SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW)
        let secret_strkey =
            stellar_strkey::ed25519::PrivateKey::from_string(
                "SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW",
            )
            .unwrap();
        let privkey = secret_strkey.0;

        let signer = StellarSigner::pubnet();
        let result = signer.sign_message(&privkey, b"Hello, World!").unwrap();

        // Verify signature matches the test vector
        use base64::Engine;
        let expected_sig = base64::engine::general_purpose::STANDARD
            .decode("fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==")
            .unwrap();

        assert_eq!(
            result.signature, expected_sig,
            "SEP-53 signature must match test vector"
        );

        // Verify the public key matches the expected address
        assert!(result.public_key.is_some());
        let pubkey = result.public_key.unwrap();
        let strkey = stellar_strkey::ed25519::PublicKey(pubkey.try_into().unwrap());
        assert_eq!(
            strkey.to_string(),
            "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L"
        );
    }

    #[test]
    fn test_sign_message_sep53_prefix() {
        let privkey = test_privkey();
        let signer = StellarSigner::pubnet();
        let message = b"test";

        let result = signer.sign_message(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());

        // Verify that the signature is over SHA256("Stellar Signed Message:\n" + message)
        let mut payload = Vec::new();
        payload.extend_from_slice(b"Stellar Signed Message:\n");
        payload.extend_from_slice(message);
        let hash: [u8; 32] = Sha256::digest(&payload).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("SEP-53 signature should verify against SHA256(prefix + message)");
    }

    #[test]
    fn test_sign_message_invalid_key() {
        let signer = StellarSigner::pubnet();
        assert!(signer.sign_message(&[], b"hello").is_err());
        assert!(signer.sign_message(&[0u8; 16], b"hello").is_err());
    }

    #[test]
    fn test_hd_derivation_integration() {
        let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
        let signer = StellarSigner::pubnet();
        let path = signer.default_derivation_path(0);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, Curve::Ed25519).unwrap();
        let address = signer.derive_address(key.expose()).unwrap();

        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
        // Known SEP-0005 vector
        assert_eq!(address, "GB3JDWCQJCWMJ3IILWIGDTQJJC5567PGVEVXSCVPEQOTDN64VJBDQBYX");
    }

    /// Build a minimal valid V0 TransactionEnvelope XDR for testing the V0→V1 conversion path.
    fn build_test_v0_envelope() -> Vec<u8> {
        use stellar_xdr::curr::*;

        let tx = TransactionV0 {
            source_account_ed25519: Uint256([0xBB; 32]),
            fee: 200,
            seq_num: SequenceNumber(42),
            time_bounds: Some(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(1_700_000_000),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionV0Ext::V0,
        };

        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });

        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn test_sign_transaction_v0_envelope() {
        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let envelope_xdr = build_test_v0_envelope();

        // sign_transaction should succeed on a V0 envelope
        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();

        // Output signature must be 64 bytes
        assert_eq!(result.signature.len(), 64, "V0 signature should be 64 bytes");
        assert!(result.public_key.is_some(), "V0 signing should return public key");

        // Verify the signature against the manually-built V1-equivalent payload
        let v0_env = match TransactionEnvelope::from_xdr(&envelope_xdr, Limits::none()).unwrap() {
            TransactionEnvelope::TxV0(v0) => v0,
            _ => panic!("expected V0 envelope"),
        };

        // Reconstruct the V1-equivalent Transaction (same logic as sign_transaction)
        use stellar_xdr::curr::{MuxedAccount, Transaction, Uint256};
        let v1_tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(
                v0_env.tx.source_account_ed25519.0,
            )),
            fee: v0_env.tx.fee,
            seq_num: v0_env.tx.seq_num.clone(),
            cond: match &v0_env.tx.time_bounds {
                Some(tb) => stellar_xdr::curr::Preconditions::Time(tb.clone()),
                None => stellar_xdr::curr::Preconditions::None,
            },
            memo: v0_env.tx.memo.clone(),
            operations: v0_env.tx.operations.clone(),
            ext: stellar_xdr::curr::TransactionExt::V0,
        };

        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(v1_tx);
        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        // Verify the Ed25519 signature
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("V0 envelope signature should verify against V1-equivalent payload");
    }

    #[test]
    fn test_sign_transaction_v0_envelope_no_timebounds() {
        // Test V0 envelope with time_bounds = None to exercise the None → Preconditions::None path
        use stellar_xdr::curr::*;

        let tx = TransactionV0 {
            source_account_ed25519: Uint256([0xCC; 32]),
            fee: 100,
            seq_num: SequenceNumber(1),
            time_bounds: None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionV0Ext::V0,
        };

        let envelope = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx,
            signatures: vec![].try_into().unwrap(),
        });
        let envelope_xdr = envelope.to_xdr(Limits::none()).unwrap();

        let privkey = test_privkey();
        let signer = StellarSigner::testnet();
        let result = signer.sign_transaction(&privkey, &envelope_xdr).unwrap();
        assert_eq!(result.signature.len(), 64, "V0 no-timebounds signature should be 64 bytes");

        // Verify signature against manually-built payload with Preconditions::None
        let v1_tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0xCC; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Inflation,
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        };

        let tagged_tx = TransactionSignaturePayloadTaggedTransaction::Tx(v1_tx);
        let network_id: [u8; 32] =
            Sha256::digest(STELLAR_PASSPHRASE_TESTNET.as_bytes()).into();
        let payload = TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id),
            tagged_transaction: tagged_tx,
        };
        let payload_xdr = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = Sha256::digest(&payload_xdr).into();

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&hash, &sig)
            .expect("V0 no-timebounds signature should verify with Preconditions::None");
    }

    #[test]
    fn test_network_passphrase_selection() {
        let pubnet = StellarSigner::pubnet();
        assert_eq!(pubnet.network_passphrase, STELLAR_PASSPHRASE_PUBNET);

        let testnet = StellarSigner::testnet();
        assert_eq!(testnet.network_passphrase, STELLAR_PASSPHRASE_TESTNET);

        let futurenet = StellarSigner::futurenet();
        assert_eq!(futurenet.network_passphrase, STELLAR_PASSPHRASE_FUTURENET);
    }
}
