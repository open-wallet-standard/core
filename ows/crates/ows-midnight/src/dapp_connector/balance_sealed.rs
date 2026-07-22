//! DApp Connector `balanceSealedTransaction` — the taker completes a maker's swap offer.
//!
//! The maker offer is **sealed** (`proof,pedersen-schnorr`), the `Transaction<SignatureEnabled, Proof,
//! Binding>` the connector spec types this method's input as. Its binding fixes its value balance, so
//! it cannot be balanced in place: it is completed by MERGING the taker's complementary half onto it —
//! see `authorize_merge`. A proven, unsealed transaction is refused; balancing one in place is what
//! `balanceUnsealed` does.
//!
//! Scope: a sealed maker offer that keeps all its value in the guaranteed section, given as hex, as a
//! MIP-0005 `swapoffer` string, or as a stringified MIP-0006 offer payload.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref as _;

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::TokenType as LedgerTokenType;
use midnight_ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use ows_core::policy::TransactionEffect;
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork};
use serde::Deserialize;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};

use super::build::{DesiredOutput, TransferKind};
use super::make_intent::{DesiredInput, MakeIntentRequest};
use super::swap_offer;
use super::{classify_unsealed_payload, ConnectorPlan, UnsealedKind};

/// A fully sealed (`proof,pedersen-schnorr`) Midnight transaction — the form a maker offer arrives in.
type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// A proven, unsealed (`proof,embedded-fr`) transaction — the taker's half before it is sealed to merge.
type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

/// A parsed `balanceSealedTransaction` request: the maker offer to complete (decoded bytes) and whether
/// the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct BalanceSealedRequest {
    pub maker_tx: Vec<u8>,
    pub pay_fees: bool,
}

fn default_pay_fees() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OptionsJson {
    #[serde(default = "default_pay_fees")]
    pay_fees: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BalanceSealedJson {
    /// The maker offer: hex, a `swapoffer` string, or a stringified MIP-0006 payload. Accepts
    /// `makerTx`, or `tx`/`transaction` as aliases.
    #[serde(alias = "tx", alias = "transaction")]
    maker_tx: String,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `balanceSealedTransaction` request into the maker offer bytes and
/// fee preference. `payFees` defaults to true.
pub fn parse_balance_sealed_json(json: &str) -> Result<BalanceSealedRequest, std::io::Error> {
    let req: BalanceSealedJson = serde_json::from_str(json).map_err(|e| {
        std::io::Error::other(format!(
            "invalid balanceSealedTransaction request JSON: {e}"
        ))
    })?;
    Ok(BalanceSealedRequest {
        maker_tx: decode_maker_input(&req.maker_tx)?,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// Decode the maker input into tagged transaction bytes: a MIP-0005 `swapoffer` string, a MIP-0006
/// payload (validated against its offer), or hex.
fn decode_maker_input(input: &str) -> Result<Vec<u8>, std::io::Error> {
    let trimmed = input.trim();
    if swap_offer::is_swap_offer(trimmed) {
        return swap_offer::decode_swap_offer(trimmed);
    }
    if trimmed.starts_with('{') {
        return swap_offer::decode_offer_payload(trimmed);
    }
    let clean = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(clean)
        .map_err(|e| std::io::Error::other(format!("invalid maker transaction hex: {e}")))
}

/// Plan a `balanceSealedTransaction`: decode the sealed maker offer and derive the taker's
/// complementary half, inertly, for the seam. Proven / preimage / non-tx payloads are rejected.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    json: &str,
) -> Result<ConnectorPlan, std::io::Error> {
    let request = parse_balance_sealed_json(json)?;
    let maker_tx = request.maker_tx;
    match classify_unsealed_payload(&maker_tx) {
        Some(UnsealedKind::Proven) => Err(std::io::Error::other(
            "balanceSealedTransaction takes a sealed (proof,pedersen-schnorr) maker offer; received a \
             proven, unsealed transaction — balance it with balanceUnsealedTransaction, or have the \
             maker seal its offer",
        )),
        Some(UnsealedKind::ProofPreimage) => Err(std::io::Error::other(
            "balanceSealedTransaction takes a sealed (proof,pedersen-schnorr) maker offer; received a \
             proof-preimage — the maker must prove and seal its own offer first",
        )),
        None if super::is_sealed_maker_payload(&maker_tx) => {
            // A sealed maker cannot be balanced in place — complete it by merging. Derive the taker's
            // complementary half here (inert, for the seam); it is built, sealed, and merged with the
            // maker in `authorize_merge`.
            let addrs = crypto_provider
                .addresses(&MidnightNetwork::from_chain_id(chain_id))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let complement =
                sealed_maker_complement(&maker_tx, &addrs.unshielded, &addrs.shielded)?;
            Ok(ConnectorPlan::BalanceSealedMerge {
                maker_tx,
                complement,
                pay_fees: request.pay_fees,
            })
        }
        None => Err(std::io::Error::other(
            "balanceSealedTransaction maker offer is not a sealed (proof,pedersen-schnorr) Midnight \
             transaction",
        )),
    }
}

// ── Sealed-maker merge (the taker's complementary half) ──────────────────────────────────────────
//
// A fully sealed maker offer cannot be balanced in place (its Pedersen-Schnorr binding fixes its value
// balance). Per the DApp Connector spec, `balanceSealed` completes it by MERGING: the taker builds its
// own imbalanced half whose per-token deltas are the exact complement of the maker's, seals it, and
// `Transaction::merge`s the two — the summed (public, in-the-clear) `binding_randomness` opens the
// summed value commitments, so the merged whole is balanced and submittable with no re-seal.
//
// This module owns the first step: reading the maker's imbalance and deriving the taker's complementary
// `makeIntent`. Building/sealing/merging that half (reusing `make_intent::authorize`) is wired in below.

/// Derive the taker's complementary `makeIntent` from the maker's per-token imbalance, as returned by
/// `Transaction::balance` (positive = maker surplus, negative = maker shortage). Each entry is negated:
/// a maker surplus of a token is one the taker RECEIVES (a desired output to the taker's own address in
/// that domain); a maker shortage is one the taker SUPPLIES (a desired input). The DUST dimension is
/// skipped — the taker's own dust pays fees. The taker's intent keys on a segment disjoint from the
/// maker's, since `Transaction::merge` rejects colliding intent segment ids.
pub(super) fn complement_from_balance(
    imbalance: BTreeMap<(LedgerTokenType, u16), i128>,
    maker_segments: &BTreeSet<u16>,
    taker_unshielded_addr: &str,
    taker_shielded_addr: &str,
) -> Result<MakeIntentRequest, std::io::Error> {
    // The taker balances the whole tx, so net each token across the maker's segments first.
    let mut per_token: BTreeMap<LedgerTokenType, i128> = BTreeMap::new();
    for ((token, _segment), bal) in imbalance {
        *per_token.entry(token).or_default() += bal;
    }

    let mut desired_inputs = Vec::new();
    let mut desired_outputs = Vec::new();
    for (token, bal) in per_token {
        let (kind, wire) = match token {
            LedgerTokenType::Unshielded(tt) => (TransferKind::Unshielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Shielded(tt) => (TransferKind::Shielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Dust => continue,
        };
        if bal > 0 {
            let recipient = match kind {
                TransferKind::Unshielded => taker_unshielded_addr,
                TransferKind::Shielded => taker_shielded_addr,
            }
            .to_string();
            desired_outputs.push(DesiredOutput {
                kind,
                token_type: wire,
                value: bal as u128,
                recipient,
            });
        } else if bal < 0 {
            desired_inputs.push(DesiredInput {
                kind,
                token_type: wire,
                value: bal.unsigned_abs(),
            });
        }
    }

    Ok(MakeIntentRequest {
        desired_inputs,
        desired_outputs,
        intent_segment: first_disjoint_segment(maker_segments)?,
    })
}

/// The lowest fallible segment (>= 1) the maker did not use. Segment 0 is the guaranteed section, where
/// the ledger rejects an intent; a collision with a maker segment fails `Transaction::merge`.
fn first_disjoint_segment(maker_segments: &BTreeSet<u16>) -> Result<u16, std::io::Error> {
    (1..=u16::MAX)
        .find(|seg| !maker_segments.contains(seg))
        .ok_or_else(|| std::io::Error::other("the maker offer leaves no free intent segment"))
}

/// Refuse a maker that moves value outside the guaranteed section. The ledger commits segment 0, then
/// applies each fallible segment on its own, so value in fallible segment N can fail apart from the
/// rest: a give the taker claims there, or a payout the maker routes straight to the taker there, is
/// dropped while the taker's payment in segment 0 stands. Swap offers keep every leg in the guaranteed
/// section for that reason (MIP-0006). A fallible contract call that moves no value is allowed.
fn ensure_value_in_guaranteed_section(
    maker: &StandardTransaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>,
    imbalance: &BTreeMap<(LedgerTokenType, u16), i128>,
) -> Result<(), std::io::Error> {
    let refuse = |segment: u16, what: &str| {
        std::io::Error::other(format!(
            "refusing a maker offer with {what} in fallible segment {segment}: the ledger applies a \
             fallible segment on its own, so it could fail while the taker's payment in segment 0 \
             stands; a swap offer keeps all its value in the guaranteed section"
        ))
    };
    for pair in maker.fallible_coins.iter() {
        let (segment, offer) = pair.deref();
        if !offer.inputs.is_empty() || !offer.outputs.is_empty() || !offer.transient.is_empty() {
            return Err(refuse(*segment.deref(), "shielded coins"));
        }
    }
    for pair in maker.intents.iter() {
        let (segment, intent) = pair.deref();
        if intent
            .fallible_unshielded_offer
            .as_ref()
            .is_some_and(|offer| !offer.inputs.is_empty() || !offer.outputs.is_empty())
        {
            return Err(refuse(*segment.deref(), "unshielded inputs or outputs"));
        }
    }
    if let Some(((_, segment), _)) = imbalance
        .iter()
        .find(|((_, segment), bal)| *segment != 0 && **bal != 0)
    {
        return Err(refuse(*segment, "an imbalance"));
    }
    Ok(())
}

/// Deserialize a sealed maker offer and derive the taker's complementary `makeIntent`, once the maker
/// is known to keep its value in the guaranteed section. The maker's tx is read in its sealed form (its
/// value balance is fixed by the binding signature); `Transaction::balance` reports the per-token
/// surplus/shortage, which [`complement_from_balance`] negates into the taker's half.
pub(super) fn sealed_maker_complement(
    maker_bytes: &[u8],
    taker_unshielded_addr: &str,
    taker_shielded_addr: &str,
) -> Result<MakeIntentRequest, std::io::Error> {
    let mut r: &[u8] = maker_bytes;
    let tx: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
    let imbalance = tx
        .balance(None)
        .map_err(|e| std::io::Error::other(format!("maker balance check failed: {e:?}")))?;
    let Transaction::Standard(base) = &tx else {
        return Err(std::io::Error::other(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    ensure_value_in_guaranteed_section(base, &imbalance)?;
    let maker_segments: BTreeSet<u16> = base
        .intents
        .iter()
        .map(|pair| {
            let (seg_sp, _intent_sp) = pair.deref();
            *seg_sp.deref()
        })
        .collect();
    complement_from_balance(
        imbalance,
        &maker_segments,
        taker_unshielded_addr,
        taker_shielded_addr,
    )
}

/// Authorize the sealed-maker merge: build the taker's complementary half from its own coins, fold in a
/// DUST fee that covers the whole *merged* tx, and return a [merge envelope](ows_signer::chains::wrap_merge_envelope)
/// of the (proven, unsealed) taker half plus the sealed maker. The sign pipeline then signs the taker's
/// own inputs, seals it, and `Transaction::merge`s it onto the maker in `encode_signed_transaction` — so
/// the taker is signed before it is sealed, and both halves are sealed for the merge, whose summed
/// in-the-clear `binding_randomness` cancels the imbalances into a balanced, submittable whole.
///
/// The maker never pays fees (`makeIntent` is imbalanced by design), so on a live-DUST chain the taker
/// funds the merged tx's fee from its own dust — sized against the merged tx and folded into the taker's
/// complement intent before it is sealed. With `pay_fees` off (or a fee-less chain) the merged tx is
/// value-balanced but fee-less, and a live-DUST network rejects the submit.
pub(super) fn authorize_merge(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_bytes: &[u8],
    complement: MakeIntentRequest,
    pay_fees: bool,
) -> Result<Vec<u8>, std::io::Error> {
    // The taker's imbalanced complementary half rides a segment disjoint from the maker's (picked in
    // `complement_from_balance`); that intent carries the DUST fee below.
    let taker_seg = complement.intent_segment;

    // The taker's imbalanced complementary half, built from its own coins (proven, still unsealed).
    let taker_unsealed = super::make_intent::authorize(chain_id, crypto_provider, complement)?;
    let mut tr: &[u8] = &taker_unsealed;
    let taker: TxProven = tagged_deserialize(&mut tr)
        .map_err(|e| std::io::Error::other(format!("failed to parse taker half: {e}")))?;
    let Transaction::Standard(mut taker_base) = taker else {
        return Err(std::io::Error::other(
            "taker complement is not a Standard transaction",
        ));
    };

    // On a live-DUST chain, size + realize the taker's DUST fee against the merged tx and fold it into
    // the taker's complement intent before the taker is sealed downstream.
    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let adding_dust = crate::balance_tx::adding_dust(pay_fees, &indexer_url)?;
    if adding_dust {
        // The maker (sealed) is needed only to size the DUST fee against the merged tx.
        let mut mr: &[u8] = maker_bytes;
        let maker: TxSealed = tagged_deserialize(&mut mr)
            .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
        attach_merge_dust_fee(
            chain_id,
            crypto_provider,
            &maker,
            &mut taker_base,
            taker_seg,
            &indexer_url,
            &scope,
        )?;
    }

    // Return a merge envelope carrying the (proven-unsealed) taker half and the sealed maker. The sign
    // pipeline signs the taker's own inputs, seals it, and `Transaction::merge`s it onto the maker in
    // `encode_signed_transaction` — reusing the exact sign/seal machinery a plain makeIntent uses, so the
    // taker is never sealed before it is signed. (`extract_signable_bytes` returns the taker to sign.)
    let mut taker_bytes = Vec::new();
    tagged_serialize(&Transaction::Standard(taker_base), &mut taker_bytes)
        .map_err(|e| std::io::Error::other(format!("serialize taker half: {e}")))?;
    Ok(ows_signer::chains::wrap_merge_envelope(
        &taker_bytes,
        maker_bytes,
    ))
}

/// The wallet-relative effects a sealed-maker MERGE will have — the taker's own half **plus** the merged
/// DUST fee it funds. The token movement is request-derived from the taker's [complement](sealed_maker_complement),
/// exactly as a plain makeIntent. On a live-DUST chain, when the taker pays fees, the fee covers the whole
/// merged tx (the maker contributes bytes but never pays), so it is sized against a **mock-proven** taker
/// complement — fixed-size proofs give the exact fee with no real proving — and folded in as a DUST
/// outflow, so a `sum(|diff|)` cap at the policy seam sees the burn. Sizing needs the same tip +
/// spendable-dust sync the real merge uses; the real, submittable spend is proved only post-seam in
/// [`authorize_merge`], so a merge denied at the seam never reaches a real proof.
pub(super) fn merge_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_bytes: &[u8],
    complement: &MakeIntentRequest,
    pay_fees: bool,
) -> Result<Vec<TransactionEffect>, std::io::Error> {
    let mut effects = super::make_intent::request_effects(chain_id, crypto_provider, complement)?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;
    if !crate::balance_tx::adding_dust(pay_fees, &indexer_url)? {
        return Ok(effects);
    }

    // Size the merged DUST fee against the taker's mock-proven complement — same coin selection as the
    // real merge, fixed-size mock proofs, no real proving. The maker (sealed) is needed only to size the
    // fee against the merged tx.
    let taker_base = super::make_intent::mock_authorize(chain_id, crypto_provider, complement)?;
    let taker_seg = complement.intent_segment;
    let binding_commitment = taker_base
        .intents
        .get(&taker_seg)
        .ok_or_else(|| std::io::Error::other("taker complement missing its intent segment"))?
        .deref()
        .binding_commitment;

    let mut mr: &[u8] = maker_bytes;
    let maker: TxSealed = tagged_deserialize(&mut mr)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;

    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let (ledger_params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(&indexer_url))?;
    let dust_ctime = Timestamp::from_secs(tip_secs);

    // Discard the synced dust state — that is only needed to prove the real, submittable spend post-seam.
    let (plan, _dust_state) = crate::balance_tx::size_merge_dust_fee(
        &maker,
        &taker_base,
        taker_seg,
        binding_commitment,
        crypto_provider,
        dust_ctime,
        &ledger_params,
        &indexer_url,
        &scope,
    )?;

    let addresses = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if let Some(effect) = crate::balance_tx::dust_outflow_effect(addresses.dust, plan.fee_dust) {
        effects.push(effect);
    }
    Ok(effects)
}

/// Size + realize the taker's DUST fee for the merge and splice it into the taker's complement intent
/// (at `dust_seg`) before sealing. The fee covers the whole *merged* tx (the maker contributes bytes but
/// never pays), so it is sized against the merged tx in [`crate::balance_tx::size_merge_dust_fee`]; the
/// converged spend is then proved in the signer ([`MidnightCryptoProvider::authorize_dust`]) and the
/// proven section attached to the taker's complement intent, whose TTL is aligned to the chain tip.
fn attach_merge_dust_fee(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker: &TxSealed,
    taker_base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_seg: u16,
    indexer_url: &str,
    scope: &SyncCacheScope,
) -> Result<(), std::io::Error> {
    // Chain time + ledger parameters fix the DUST fee and the intent's TTL.
    let (ledger_params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(indexer_url))?;
    let dust_ctime = Timestamp::from_secs(tip_secs);

    // The DUST section rides the taker's complement intent (which carries none), proved against that
    // intent's own binding commitment so the two stay bound together through the merge.
    let binding_commitment = taker_base
        .intents
        .get(&dust_seg)
        .ok_or_else(|| std::io::Error::other("taker half missing the complement intent segment"))?
        .deref()
        .binding_commitment;

    // Size against the merged tx (offline, mock-proved), then prove the real, submittable spend.
    let (plan, dust_state) = crate::balance_tx::size_merge_dust_fee(
        maker,
        taker_base,
        dust_seg,
        binding_commitment,
        crypto_provider,
        dust_ctime,
        &ledger_params,
        indexer_url,
        scope,
    )?;
    let prover = crate::balance_tx::midnight_prover(chain_id)?;
    let dust_actions =
        crate::block_on(crypto_provider.authorize_dust(&dust_state, &plan, &ledger_params, prover))
            .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Splice the proven DUST section into the taker's complement intent, aligning its TTL to the tip
    // (the section's fee window is anchored at `dust_ctime`).
    let mut intent = taker_base
        .intents
        .get(&dust_seg)
        .ok_or_else(|| std::io::Error::other("taker half missing the complement intent segment"))?
        .deref()
        .clone();
    intent.dust_actions = Some(Sp::new(dust_actions));
    intent.ttl = plan.intent_ttl;
    taker_base.intents = taker_base.intents.insert(dust_seg, intent);
    Ok(())
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::{ShieldedTokenType, UnshieldedTokenType};

    fn shielded(b: u8) -> LedgerTokenType {
        LedgerTokenType::Shielded(ShieldedTokenType(HashOutput([b; 32])))
    }
    fn unshielded(b: u8) -> LedgerTokenType {
        LedgerTokenType::Unshielded(UnshieldedTokenType(HashOutput([b; 32])))
    }

    #[test]
    fn complement_negates_imbalance_and_maps_domains() {
        // Maker gives 100 of a shielded token (surplus, +) and wants 50 unshielded NIGHT (shortage, -).
        let mut bal = BTreeMap::new();
        bal.insert((shielded(0xAA), 1u16), 100i128);
        bal.insert((unshielded(0x00), 1u16), -50i128);

        let req = complement_from_balance(
            bal,
            &BTreeSet::from([1u16]),
            "taker_unshielded",
            "taker_shielded",
        )
        .unwrap();

        // The taker RECEIVES the maker's surplus as an output to its own shielded address.
        assert_eq!(req.desired_outputs.len(), 1);
        let out = &req.desired_outputs[0];
        assert_eq!(out.kind, TransferKind::Shielded);
        assert_eq!(out.value, 100);
        assert_eq!(out.recipient, "taker_shielded");
        assert_eq!(out.token_type, hex::encode([0xAAu8; 32]));

        // The taker SUPPLIES the maker's shortage as an input.
        assert_eq!(req.desired_inputs.len(), 1);
        let inp = &req.desired_inputs[0];
        assert_eq!(inp.kind, TransferKind::Unshielded);
        assert_eq!(inp.value, 50);
        assert_eq!(inp.token_type, hex::encode([0x00u8; 32]));

        // The taker's intent must not collide with the maker's segment (maker used 1 → taker gets 2).
        assert_eq!(req.intent_segment, 2);
    }

    #[test]
    fn nets_a_token_across_segments() {
        // Same token, split across two maker segments: +100 and -30 net to +70 (a single taker output).
        let mut bal = BTreeMap::new();
        bal.insert((shielded(0x01), 1u16), 100i128);
        bal.insert((shielded(0x01), 2u16), -30i128);

        let req = complement_from_balance(bal, &BTreeSet::from([1u16, 2u16]), "u", "s").unwrap();

        assert_eq!(req.desired_inputs.len(), 0);
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.desired_outputs[0].value, 70);
        // Maker used 1 and 2 → the taker's disjoint segment is 3.
        assert_eq!(req.intent_segment, 3);
    }

    #[test]
    fn errors_when_the_maker_leaves_no_free_segment() {
        let all: BTreeSet<u16> = (1..=u16::MAX).collect();
        assert!(first_disjoint_segment(&all).is_err());
        assert_eq!(
            first_disjoint_segment(&BTreeSet::from([u16::MAX])).unwrap(),
            1
        );
    }

    #[test]
    fn dust_dimension_is_skipped() {
        let mut bal = BTreeMap::new();
        bal.insert((LedgerTokenType::Dust, 1u16), -1000i128);

        let req = complement_from_balance(bal, &BTreeSet::new(), "u", "s").unwrap();

        assert!(req.desired_inputs.is_empty());
        assert!(req.desired_outputs.is_empty());
        assert_eq!(req.intent_segment, 1);
    }

    #[test]
    fn complement_of_a_real_sealed_maker_negates_its_balance() {
        // A real preprod makeIntent output — proof,pedersen-schnorr, sealed and imbalanced.
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex");
        let hex_str = hex_str.trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();

        // The maker's own imbalance, straight from the ledger (balance() works on the sealed marker).
        let mut r: &[u8] = &bytes;
        let tx: TxSealed = tagged_deserialize(&mut r).unwrap();
        let mut maker: BTreeMap<String, i128> = BTreeMap::new();
        for ((token, _seg), bal) in tx.balance(None).unwrap() {
            let wire = match token {
                LedgerTokenType::Unshielded(tt) => hex::encode(tt.0 .0),
                LedgerTokenType::Shielded(tt) => hex::encode(tt.0 .0),
                LedgerTokenType::Dust => continue,
            };
            *maker.entry(wire).or_default() += bal;
        }
        assert!(!maker.is_empty(), "the fixture must carry a real imbalance");

        // The taker's complement, netted back per token in balance() convention: input supplies (+),
        // output absorbs (-). Merging it onto the maker must zero every token, i.e. taker == -maker.
        let req = sealed_maker_complement(&bytes, "taker_unshielded", "taker_shielded").unwrap();
        let mut taker: BTreeMap<String, i128> = BTreeMap::new();
        for inp in &req.desired_inputs {
            *taker.entry(inp.token_type.clone()).or_default() += inp.value as i128;
        }
        for out in &req.desired_outputs {
            *taker.entry(out.token_type.clone()).or_default() -= out.value as i128;
        }
        for (token, m) in &maker {
            assert_eq!(
                taker.get(token).copied().unwrap_or(0),
                -*m,
                "token {token}: taker must negate the maker's imbalance"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maker_tx_hex_and_defaults_pay_fees() {
        let req = parse_balance_sealed_json(
            r#"{"method":"balanceSealedTransaction","makerTx":"0x0102ab"}"#,
        )
        .unwrap();
        assert_eq!(req.maker_tx, vec![0x01, 0x02, 0xab]);
        assert!(req.pay_fees);
    }

    #[test]
    fn accepts_tx_alias_and_pay_fees_false() {
        let req = parse_balance_sealed_json(r#"{"tx":"00","options":{"payFees":false}}"#).unwrap();
        assert_eq!(req.maker_tx, vec![0x00]);
        assert!(!req.pay_fees);
    }

    #[test]
    fn rejects_non_hex_maker_tx() {
        assert!(parse_balance_sealed_json(r#"{"makerTx":"zz"}"#).is_err());
    }

    #[test]
    fn a_swapoffer_maker_decodes_to_the_sealed_offer() {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        let sealed = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let json = format!(
            r#"{{"makerTx":"{}"}}"#,
            swap_offer::encode_swap_offer(&sealed)
        );
        let req = parse_balance_sealed_json(&json).unwrap();
        assert_eq!(req.maker_tx, sealed);
        assert!(super::super::is_sealed_maker_payload(&req.maker_tx));
    }

    #[test]
    fn a_stringified_payload_maker_is_validated_against_its_offer() {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        let sealed = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        // The fixture gives NIGHT and wants nothing, so its payload is refused as one-sided.
        let payload = serde_json::json!({
            "version": 1,
            "offerBech32": swap_offer::encode_swap_offer(&sealed),
            "computed": {
                "gives": [{ "token": "00".repeat(32), "amount": "500000", "type": "UNSHIELDED" }],
                "wants": [],
            },
        });
        let json = serde_json::json!({ "makerTx": payload.to_string() }).to_string();
        let e = parse_balance_sealed_json(&json).unwrap_err();
        assert!(e.to_string().contains("one-sided"), "{e}");
    }

    #[test]
    fn sealed_maker_input_is_recognized_as_sealed() {
        // A fully sealed maker blob (proof,pedersen-schnorr tag) decodes as raw bytes and is
        // recognized as sealed, so plan() takes the precise sealed-merge error path rather than the
        // generic fallthrough.
        let sealed_tag = b"midnight:transaction[v9](signature[v1],proof,pedersen-schnorr[v1]):";
        let mut blob = sealed_tag.to_vec();
        blob.extend_from_slice(&[0u8; 8]);
        let json = format!(r#"{{"makerTx":"{}"}}"#, hex::encode(&blob));
        let req = parse_balance_sealed_json(&json).unwrap();
        assert!(super::super::is_sealed_maker_payload(&req.maker_tx));
        assert_eq!(classify_unsealed_payload(&req.maker_tx), None);
    }

    mod placement {
        use super::*;
        use midnight_base_crypto::hash::HashOutput;
        use midnight_base_crypto::signatures::SigningKey;
        use midnight_coin_structure::coin::{
            Commitment, ShieldedTokenType, UnshieldedTokenType, UserAddress, NIGHT,
        };
        use midnight_ledger::structure::{
            Intent, IntentHash, UnshieldedOffer, UtxoOutput, UtxoSpend,
        };
        use midnight_storage::storage::HashMap as MnHashMap;
        use midnight_zswap::{Delta, Offer as ZswapOffer, Output};
        use rand::rngs::StdRng;
        use rand::SeedableRng as _;
        use std::sync::Arc;
        use transient_crypto::commitment::Pedersen;
        use transient_crypto::proofs::Proof;

        type ProvenBase = StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;
        type Unshielded = Option<Sp<UnshieldedOffer<MnSig, InMemoryDB>>>;

        fn key(b: u8) -> UserAddress {
            UserAddress::from(SigningKey::from_bytes(&[b; 32]).unwrap().verifying_key())
        }

        /// The maker gives 600 000 NIGHT: it spends 1 000 000 and keeps 400 000 as [`change`].
        fn give() -> UtxoSpend {
            UtxoSpend {
                value: 1_000_000,
                owner: SigningKey::from_bytes(&[0x11; 32]).unwrap().verifying_key(),
                type_: NIGHT,
                intent_hash: IntentHash(HashOutput([7; 32])),
                output_no: 0,
            }
        }

        fn change() -> UtxoOutput {
            UtxoOutput {
                value: 400_000,
                owner: key(0x11),
                type_: NIGHT,
            }
        }

        /// The maker wants 50 of an unshielded token.
        fn want() -> UtxoOutput {
            UtxoOutput {
                value: 50,
                owner: key(0x11),
                type_: UnshieldedTokenType(HashOutput([0x22; 32])),
            }
        }

        fn offer(inputs: Vec<UtxoSpend>, outputs: Vec<UtxoOutput>) -> Unshielded {
            Some(Sp::new(UnshieldedOffer {
                inputs: inputs.into(),
                outputs: outputs.into(),
                signatures: vec![].into(),
            }))
        }

        /// A maker whose intent 1 carries `guaranteed` (segment 0) and `fallible` (segment 1).
        fn maker(guaranteed: Unshielded, fallible: Unshielded) -> ProvenBase {
            let intent = Intent {
                guaranteed_unshielded_offer: guaranteed,
                fallible_unshielded_offer: fallible,
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

        /// `maker` with a shielded offer in fallible segment 1.
        fn with_fallible_coins(
            mut maker: ProvenBase,
            coins: ZswapOffer<Proof, InMemoryDB>,
        ) -> ProvenBase {
            maker.fallible_coins = maker.fallible_coins.insert(1, coins);
            maker
        }

        fn sealed(maker: ProvenBase) -> Vec<u8> {
            let mut out = Vec::new();
            tagged_serialize(
                &Transaction::Standard(maker).seal(StdRng::seed_from_u64(0)),
                &mut out,
            )
            .unwrap();
            out
        }

        fn complement(maker: ProvenBase) -> Result<MakeIntentRequest, std::io::Error> {
            sealed_maker_complement(&sealed(maker), "taker_unshielded", "taker_shielded")
        }

        fn assert_refused(maker: ProvenBase, what: &str) {
            let e = complement(maker).expect_err(what);
            assert!(e.to_string().contains("fallible segment 1"), "{what}: {e}");
        }

        #[test]
        fn completes_a_maker_whose_legs_all_sit_in_the_guaranteed_section() {
            let req = complement(maker(offer(vec![give()], vec![change(), want()]), None)).unwrap();
            assert_eq!(req.desired_outputs.len(), 1);
            assert_eq!(req.desired_outputs[0].value, 600_000);
            assert_eq!(req.desired_inputs.len(), 1);
            assert_eq!(req.desired_inputs[0].value, 50);
        }

        #[test]
        fn refuses_a_leg_in_a_fallible_segment() {
            assert_refused(
                maker(
                    offer(vec![], vec![want()]),
                    offer(vec![give()], vec![change()]),
                ),
                "a give in segment 1",
            );
            assert_refused(
                maker(
                    offer(vec![give()], vec![change()]),
                    offer(vec![], vec![want()]),
                ),
                "a want in segment 1",
            );
            assert_refused(
                maker(None, offer(vec![give()], vec![change(), want()])),
                "both legs in segment 1",
            );
        }

        #[test]
        fn refuses_a_payout_routed_to_the_taker_in_a_fallible_segment() {
            // The 600 000 goes straight to the taker in segment 1, which then nets to zero and leaves
            // nothing to claim, while the want is paid in segment 0.
            let payout = UtxoOutput {
                value: 600_000,
                owner: key(0x33),
                type_: NIGHT,
            };
            assert_refused(
                maker(
                    offer(vec![], vec![want()]),
                    offer(vec![give()], vec![change(), payout]),
                ),
                "an unshielded payout in segment 1",
            );
            let shielded_payout = Output {
                coin_com: Commitment(HashOutput([0x44; 32])),
                value_commitment: Pedersen(Default::default()),
                contract_address: None,
                ciphertext: None,
                proof: Arc::new(Proof(vec![])),
            };
            let coins = ZswapOffer {
                inputs: vec![].into(),
                outputs: vec![shielded_payout].into(),
                transient: vec![].into(),
                deltas: vec![].into(),
            };
            assert_refused(
                with_fallible_coins(maker(offer(vec![], vec![want()]), None), coins),
                "a shielded payout in segment 1",
            );
        }

        #[test]
        fn refuses_value_a_fallible_segment_creates() {
            // A shielded surplus in segment 1 with no coin behind it, as a contract mint there leaves.
            let minted = ZswapOffer {
                inputs: vec![].into(),
                outputs: vec![].into(),
                transient: vec![].into(),
                deltas: vec![Delta {
                    token_type: ShieldedTokenType(HashOutput([0x55; 32])),
                    value: 600_000,
                }]
                .into(),
            };
            assert_refused(
                with_fallible_coins(maker(offer(vec![], vec![want()]), None), minted),
                "a surplus in segment 1",
            );
        }

        fn provider() -> MidnightCryptoProvider {
            use ows_signer::chains::MidnightSigner;
            use ows_signer::SecretBytes;
            let mut credential = b"MNK1".to_vec();
            credential.extend_from_slice(&[0x11; 96]);
            MidnightSigner::mainnet()
                .crypto_provider(&SecretBytes::new(credential))
                .unwrap()
        }

        fn plan_maker(maker_tx: &[u8]) -> Result<ConnectorPlan, std::io::Error> {
            let json = serde_json::json!({
                "method": "balanceSealedTransaction",
                "makerTx": hex::encode(maker_tx),
            })
            .to_string();
            plan("midnight:preview", &provider(), &json)
        }

        #[test]
        fn plan_refuses_a_proven_maker_and_a_split_sealed_one() {
            let mut proven = Vec::new();
            tagged_serialize(
                &Transaction::Standard(maker(offer(vec![give()], vec![change(), want()]), None)),
                &mut proven,
            )
            .unwrap();
            let e = plan_maker(&proven)
                .err()
                .expect("a proven maker is refused");
            assert!(e.to_string().contains("balanceUnsealedTransaction"), "{e}");

            let split = sealed(maker(
                offer(vec![], vec![want()]),
                offer(vec![give()], vec![change()]),
            ));
            let e = plan_maker(&split).err().expect("a split maker is refused");
            assert!(e.to_string().contains("fallible segment 1"), "{e}");
        }
    }
}
