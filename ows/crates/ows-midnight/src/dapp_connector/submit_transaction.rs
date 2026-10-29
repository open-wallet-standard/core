//! DApp Connector `submitTransaction`.
//!
//! `submitTransaction(tx)` asks the wallet to broadcast a transaction that is already sealed and
//! balanced: one `ows sign tx` returned, or one a dapp completed elsewhere. The wallet proves, signs and
//! pays for nothing, so this needs no key. It runs the check every sealed submit runs, the ledger's own
//! per-segment balance, and sends the bytes unchanged, so a submit that timed out can be retried with
//! the very transaction that may already have landed. The request has to name the method: a bare sealed
//! transaction stays a maker offer to complete, since the bytes alone cannot say which was meant.

use midnight_ledger::structure::Transaction;
use midnight_serialize::tagged_deserialize;
use serde::Deserialize;

use super::build::err;
use super::{classify_unsealed_payload, is_sealed_maker_payload, UnsealedKind};
use crate::policy_context::{FeeContext, PolicyContext};

/// A checked `submitTransaction` request: a sealed transaction built for the request's network, which
/// the node's balance check will not refuse.
#[derive(Debug, Clone)]
pub struct SubmitTransactionRequest {
    tx: Vec<u8>,
}

#[derive(Deserialize)]
struct SubmitTransactionJson {
    /// The sealed transaction, hex-encoded. A top-level `method` key routes the request upstream and
    /// is ignored here.
    tx: String,
}

/// Parse a stringified DApp Connector `submitTransaction` request for `chain_id` and check its
/// transaction: it must be sealed (`proof,pedersen-schnorr`), parse whole, carry `chain_id`'s network
/// id, and leave no segment short of any token.
pub fn parse_submit_transaction_json(
    chain_id: &str,
    json: &str,
) -> Result<SubmitTransactionRequest, std::io::Error> {
    let req: SubmitTransactionJson = serde_json::from_str(json)
        .map_err(|e| err(format!("invalid submitTransaction request JSON: {e}")))?;
    let trimmed = req.tx.trim();
    let tx = hex::decode(trimmed.strip_prefix("0x").unwrap_or(trimmed))
        .map_err(|e| err(format!("invalid submitTransaction transaction hex: {e}")))?;
    match classify_unsealed_payload(&tx) {
        Some(UnsealedKind::Proven) => return Err(err(
            "submitTransaction takes a sealed (proof,pedersen-schnorr) transaction; received a \
                 proven, unsealed one, which balanceUnsealedTransaction balances and seals",
        )),
        Some(UnsealedKind::ProofPreimage) => return Err(err(
            "submitTransaction takes a sealed (proof,pedersen-schnorr) transaction; received a \
                 proof-preimage, which has to be proven, balanced and sealed first",
        )),
        None if !is_sealed_maker_payload(&tx) => {
            return Err(err(
                "submitTransaction transaction is not a sealed (proof,pedersen-schnorr) Midnight \
                 transaction",
            ))
        }
        None => {}
    }
    let mut r: &[u8] = &tx;
    let sealed: crate::submit::SealedTx = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse the sealed transaction: {e}")))?;
    if let Transaction::Standard(stx) = &sealed {
        crate::balance_tx::ensure_tx_network_id_matches_chain(chain_id, &stx.network_id)?;
    }
    crate::submit::preflight_sealed_tx_submit(&sealed)?;
    Ok(SubmitTransactionRequest { tx })
}

impl SubmitTransactionRequest {
    /// The sealed bytes, exactly as the request carried them.
    pub fn transaction(&self) -> &[u8] {
        &self.tx
    }

    /// The `chain_extra` context a token's policies gate the submit on. The wallet authorizes nothing
    /// here: whatever the transaction moves was signed before it was sealed. So the context is that of
    /// a request that moves nothing, with no effects, contracts, fee or registration.
    pub fn policy_context(&self) -> Result<serde_json::Value, std::io::Error> {
        let context = PolicyContext {
            segment_effects: Vec::new(),
            contracts: Vec::new(),
            fee: FeeContext::none(),
            dust_registrations: Vec::new(),
            offer: None,
        };
        serde_json::to_value(&context).map_err(|e| err(e.to_string()))
    }

    /// Broadcast the transaction to the node at `node_rpc_url` and return its ledger hash.
    pub fn submit(&self, node_rpc_url: &str) -> Result<String, std::io::Error> {
        crate::submit::broadcast_sealed(node_rpc_url, &self.tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_base_crypto::signatures::{Signature as MnSig, SigningKey};
    use midnight_base_crypto::time::Timestamp;
    use midnight_coin_structure::coin::{UserAddress, NIGHT};
    use midnight_ledger::structure::{
        Intent, IntentHash, ProofMarker, StandardTransaction, UnshieldedOffer, UtxoOutput,
        UtxoSpend,
    };
    use midnight_serialize::tagged_serialize;
    use midnight_storage::arena::Sp;
    use midnight_storage::db::InMemoryDB;
    use midnight_storage::storage::HashMap as MnHashMap;
    use rand::rngs::StdRng;
    use rand::SeedableRng as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use transient_crypto::commitment::PedersenRandomness;

    type ProvenBase = StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

    const CHAIN: &str = "midnight:preview";

    /// A preview transaction whose intent 1 spends a 1 000 000 NIGHT coin into `outputs` in the
    /// guaranteed section. Its input is unsigned, which the node refuses and the balance check does not
    /// look at.
    fn spending_into(outputs: &[u128]) -> ProvenBase {
        let owner = SigningKey::from_bytes(&[0x11; 32]).unwrap().verifying_key();
        let offer = UnshieldedOffer {
            inputs: vec![UtxoSpend {
                value: 1_000_000,
                owner: owner.clone(),
                type_: NIGHT,
                intent_hash: IntentHash(HashOutput([7; 32])),
                output_no: 0,
            }]
            .into(),
            outputs: outputs
                .iter()
                .map(|&value| UtxoOutput {
                    value,
                    owner: UserAddress::from(owner.clone()),
                    type_: NIGHT,
                })
                .collect::<Vec<_>>()
                .into(),
            signatures: vec![].into(),
        };
        let intent = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(offer)),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        StandardTransaction {
            network_id: "preview".to_string(),
            intents: MnHashMap::new().insert(1, intent),
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        }
    }

    fn sealed(base: ProvenBase) -> Vec<u8> {
        let mut out = Vec::new();
        tagged_serialize(
            &Transaction::Standard(base).seal(StdRng::seed_from_u64(0)),
            &mut out,
        )
        .unwrap();
        out
    }

    /// A sealed preview transaction that moves 1 000 000 NIGHT to 400 000 and 600 000: balanced.
    fn balanced() -> Vec<u8> {
        sealed(spending_into(&[400_000, 600_000]))
    }

    fn request(tx: &[u8]) -> String {
        serde_json::json!({ "method": "submitTransaction", "tx": hex::encode(tx) }).to_string()
    }

    fn refusal(tx: &[u8]) -> String {
        parse_submit_transaction_json(CHAIN, &request(tx))
            .unwrap_err()
            .to_string()
    }

    /// `ows-lib`'s send tests carry this transaction as a checked-in fixture, since that crate cannot
    /// build one; it is the transaction built here.
    #[test]
    fn the_balanced_fixture_is_the_transaction_built_here() {
        assert_eq!(
            include_str!("testdata/sealed_balanced_preview.hex").trim(),
            hex::encode(balanced())
        );
    }

    #[test]
    fn a_balanced_sealed_transaction_is_submitted_unchanged() {
        let tx = balanced();
        let submission = parse_submit_transaction_json(CHAIN, &request(&tx)).unwrap();
        assert_eq!(submission.transaction(), tx.as_slice());

        let with_prefix =
            serde_json::json!({ "tx": format!("0x{}", hex::encode(&tx)) }).to_string();
        let submission = parse_submit_transaction_json(CHAIN, &with_prefix).unwrap();
        assert_eq!(submission.transaction(), tx.as_slice());
    }

    /// The wallet signs nothing in a submit, so the policy sees a request that moves nothing.
    #[test]
    fn a_submission_moves_nothing_for_the_policy() {
        let submission = parse_submit_transaction_json(CHAIN, &request(&balanced())).unwrap();
        assert_eq!(
            submission.policy_context().unwrap(),
            serde_json::json!({
                "segment_effects": [],
                "contracts": [],
                "fee": { "mode": "none", "dust_burned": "0" },
                "dust_registrations": [],
            })
        );
    }

    /// A maker offer, which the taker still has to complete, is short of what it wants: the node would
    /// reject it as overspent.
    #[test]
    fn an_imbalanced_transaction_is_refused() {
        let e = refusal(&sealed(spending_into(&[400_000, 700_000])));
        assert!(e.contains("imbalanced"), "{e}");
        assert!(e.contains("BalanceCheckOverspend"), "{e}");
    }

    #[test]
    fn a_transaction_for_another_network_is_refused() {
        let mut mainnet = spending_into(&[400_000, 600_000]);
        mainnet.network_id = "mainnet".to_string();
        let e = refusal(&sealed(mainnet));
        assert!(e.contains("network id"), "{e}");
    }

    #[test]
    fn anything_but_a_whole_sealed_transaction_is_refused() {
        let mut proven = Vec::new();
        tagged_serialize(
            &Transaction::Standard(spending_into(&[400_000, 600_000])),
            &mut proven,
        )
        .unwrap();
        assert!(
            refusal(&proven).contains("balanceUnsealedTransaction"),
            "a proven, unsealed transaction"
        );

        let mut trailing = balanced();
        trailing.push(0);
        assert!(
            refusal(&trailing).contains("failed to parse"),
            "trailing bytes"
        );

        let tagged_only = b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";
        assert!(
            refusal(tagged_only).contains("failed to parse"),
            "a bare tag"
        );
        assert!(refusal(b"\x00\x01").contains("not a sealed"), "not a tx");

        for bad in [
            r#"{"method":"submitTransaction","tx":"zz"}"#,
            r#"{"method":"submitTransaction"}"#,
        ] {
            assert!(parse_submit_transaction_json(CHAIN, bad).is_err(), "{bad}");
        }
    }

    /// A balanced transaction is handed to the node the caller names. The listener speaks no node
    /// protocol, so the submit fails after connecting; a refused transaction never connects at all.
    #[test]
    fn only_a_checked_transaction_reaches_the_node() {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let node = format!("ws://{}", listener.local_addr().unwrap());
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        std::thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                counted.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = conn.read(&mut buf);
            }
        });

        let refused = sealed(spending_into(&[400_000, 700_000]));
        assert!(crate::submit::broadcast_sealed(&node, &refused).is_err());
        assert_eq!(connections.load(Ordering::SeqCst), 0);

        let submission = parse_submit_transaction_json(CHAIN, &request(&balanced())).unwrap();
        let e = submission.submit(&node).unwrap_err().to_string();
        assert!(e.contains("Midnight node RPC"), "{e}");
        assert!(connections.load(Ordering::SeqCst) >= 1);
    }
}
