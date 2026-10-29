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
use std::path::Path;

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{TokenType as LedgerTokenType, UserAddress};
use midnight_ledger::structure::{ProofMarker, StandardTransaction, Transaction};
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork};
use serde::Deserialize;
use transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};

use super::build::{DesiredOutput, TransferKind};
use super::make_intent::{DesiredInput, MakeIntentRequest, OfferPlan};
use super::swap_offer;
use super::{classify_unsealed_payload, ConnectorPlan, UnsealedKind};

/// A fully sealed (`proof,pedersen-schnorr`) Midnight transaction — the form a maker offer arrives in.
type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

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

/// The spec's options bag. Any other key is refused rather than ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    vault_path: Option<&Path>,
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
            // A sealed maker cannot be balanced in place — complete it by merging. Decide the taker's
            // complementary half and its DUST fee here (inert, for the seam); exactly that half is
            // proven, sealed, and merged with the maker in `authorize_merge`.
            let addrs = crypto_provider
                .addresses(&MidnightNetwork::from_chain_id(chain_id))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let complement =
                sealed_maker_complement(chain_id, &maker_tx, &addrs.unshielded, &addrs.shielded)?;
            super::maker_checks::check_maker(chain_id, &maker_tx, vault_path)?;
            let merge = plan_merge(
                chain_id,
                crypto_provider,
                maker_tx,
                complement,
                request.pay_fees,
                vault_path,
            )?;
            Ok(ConnectorPlan::BalanceSealedMerge(Box::new(merge)))
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
// `makeIntent`. Planning, proving and merging that half (reusing makeIntent's `OfferPlan`) is wired in
// below.

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
        // The complement's own expiry never reaches the chain: the merge path rebuilds the taker's intent
        // with a tip-aligned TTL. Only the maker's sealed TTL bounds when the merged tx can still land.
        ttl: None,
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
    chain_id: &str,
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
    // A maker built for another network would only fail at the merge, after the taker's half is proven.
    crate::balance_tx::ensure_tx_network_id_matches_chain(chain_id, &base.network_id)?;
    ensure_value_in_guaranteed_section(base, &imbalance)?;
    let maker_segments: BTreeSet<u16> = base
        .intents
        .iter()
        .map(|pair| {
            let (seg_sp, _intent_sp) = pair.deref();
            *seg_sp.deref()
        })
        .collect();
    let complement = complement_from_balance(
        imbalance,
        &maker_segments,
        taker_unshielded_addr,
        taker_shielded_addr,
    )?;
    // MIP-0006: a taker settles only an offer that both gives and wants, whatever form it came in. A
    // want-only "offer" would have the taker pay with nothing in return.
    match (
        complement.desired_inputs.is_empty(),
        complement.desired_outputs.is_empty(),
    ) {
        (false, false) => Ok(complement),
        (true, true) => Err(std::io::Error::other(
            "the maker transaction is already balanced, so there is nothing for a taker to \
             complete; paying the fee of another transaction is not supported",
        )),
        _ => Err(std::io::Error::other(
            "refusing a one-sided maker offer: a swap must both give and want a token (MIP-0006)",
        )),
    }
}

/// The contract actions a sealed maker offer carries. A merge preserves both halves' intents verbatim,
/// so the maker's contract actions — the taker's complement adds none — are exactly what the submitted
/// transaction performs, at the maker's own segments.
pub(super) fn maker_contracts(
    maker_bytes: &[u8],
    wallet: &UserAddress,
) -> Result<Vec<crate::contracts::ContractInteraction>, std::io::Error> {
    let mut r: &[u8] = maker_bytes;
    let tx: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
    let Transaction::Standard(base) = &tx else {
        return Err(std::io::Error::other(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    Ok(crate::contracts::contract_interactions(
        base.actions(),
        wallet,
    ))
}

/// A sealed-maker merge decided before the policy seam: the maker's sealed bytes, the taker's
/// complementary request (what the seam's token effects are read from), the taker's half planned but not
/// proven (its frame, with the coins it spends), and the DUST fee covering the whole merged transaction
/// when the taker pays one. [`authorize_merge`] proves exactly this half and pays exactly this fee, so
/// the merge the policy saw is the one signed.
pub struct MergePlan {
    maker_tx: Vec<u8>,
    complement: MakeIntentRequest,
    taker: OfferPlan,
    fee: Option<MergeFee>,
}

/// How the taker pays the merged transaction's fee, decided before the policy seam.
enum MergeFee {
    /// A generationless registration of NIGHT the taker's half spends: final as planned, and signed
    /// with the rest of the half.
    Registration(Box<crate::balance_tx::MergeRegistrationFee>),
    /// A proof-bearing spend of DUST the taker holds, proved after the policy seam.
    Spend(Box<crate::balance_tx::MergeDustFee>),
}

impl MergeFee {
    /// The DUST the fee takes out of what the taker holds: a registration pays from DUST its NIGHT has
    /// generated and not yet been credited with, so it takes none.
    fn dust_outflow(&self) -> u128 {
        match self {
            MergeFee::Registration(_) => 0,
            MergeFee::Spend(spend) => spend.plan.fee_dust,
        }
    }

    fn binding_commitment(&self) -> PedersenRandomness {
        match self {
            MergeFee::Registration(reg) => reg.binding_commitment,
            MergeFee::Spend(spend) => spend.plan.binding_commitment,
        }
    }
}

impl MergePlan {
    /// The maker's sealed bytes, whose contract actions survive the merge into the submitted
    /// transaction.
    pub(super) fn maker_tx(&self) -> &[u8] {
        &self.maker_tx
    }

    /// How the taker pays the merged transaction's fee, and the most DUST that can take.
    pub(super) fn fee_context(&self) -> crate::policy_context::FeeContext {
        match &self.fee {
            Some(MergeFee::Registration(reg)) => {
                crate::policy_context::FeeContext::registration(reg.allow_fee_payment())
            }
            Some(MergeFee::Spend(spend)) => {
                crate::policy_context::FeeContext::spend(spend.plan.fee_dust)
            }
            None => crate::policy_context::FeeContext::none(),
        }
    }

    /// The dust registration the taker signs: its fee registration, when one pays the fee, riding its
    /// complement intent. It registers the wallet's NIGHT to the wallet's own DUST address.
    pub(super) fn dust_registrations(
        &self,
        addresses: &ows_signer::chains::midnight::MidnightAddresses,
    ) -> Vec<crate::policy_context::DustRegistrationContext> {
        let Some(MergeFee::Registration(reg)) = &self.fee else {
            return Vec::new();
        };
        vec![crate::policy_context::DustRegistrationContext {
            intent_id: self.complement.intent_segment,
            carried: false,
            night_address: addresses.unshielded.clone(),
            dust_address: addresses.dust.clone(),
            own: true,
            allow_fee_payment: reg.allow_fee_payment().to_string(),
            replaces_delegation: None,
        }]
    }
}

/// Plan the merge: decide the taker's half and, on a live-DUST chain when the taker pays fees, size the
/// fee against the merged transaction. The fee covers the whole merged tx (the maker contributes bytes
/// but never pays), so it is sized against the taker's half **mock-proven**: fixed-size proofs give the
/// exact fee with no real proving, so a merge denied at the seam never reaches a real proof.
///
/// As for the wallet's own transactions, a generationless registration pays the fee when the wallet
/// holds unregistered NIGHT that has generated enough DUST, and a spend of DUST it holds pays it
/// otherwise. The registration draws only on NIGHT its intent spends, so the half also spends the
/// wallet's best unregistered coin, returning it whole; a half paying by a spend does not, since the
/// extra coin would only add to the merged transaction's cost.
fn plan_merge(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_tx: Vec<u8>,
    complement: MakeIntentRequest,
    pay_fees: bool,
    vault_path: Option<&Path>,
) -> Result<MergePlan, std::io::Error> {
    let (taker, fee) = plan_taker_half(
        chain_id,
        crypto_provider,
        &maker_tx,
        &complement,
        pay_fees,
        vault_path,
    )?;
    Ok(MergePlan {
        maker_tx,
        complement,
        taker,
        fee,
    })
}

/// The taker's half of [`plan_merge`] and the fee it pays.
fn plan_taker_half(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker_tx: &[u8],
    complement: &MakeIntentRequest,
    pay_fees: bool,
    vault_path: Option<&Path>,
) -> Result<(OfferPlan, Option<MergeFee>), std::io::Error> {
    let indexer_url = crate::wallet::resolve_indexer_url(chain_id, vault_path)?;
    let paying = crate::balance_tx::adding_dust(pay_fees, &indexer_url)?;
    let spends_unshielded = complement
        .desired_inputs
        .iter()
        .any(|d| d.kind == TransferKind::Unshielded);
    let pool = if paying || spends_unshielded {
        super::make_intent::wallet_unshielded_pool(chain_id, crypto_provider, vault_path)?
    } else {
        Vec::new()
    };
    if !paying {
        let taker = super::make_intent::plan_offer_from_pool(
            chain_id,
            crypto_provider,
            complement,
            &pool,
            None,
            vault_path,
        )?;
        return Ok((taker, None));
    }

    let (ledger_params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(&indexer_url))?;
    let tip = Timestamp::from_secs(tip_secs);
    let mut mr: &[u8] = maker_tx;
    let maker: TxSealed = tagged_deserialize(&mut mr)
        .map_err(|e| std::io::Error::other(format!("failed to parse sealed maker tx: {e}")))?;
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .unshielded;
    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let reserve = crate::balance_tx::reserve_for_merge_fee_registration(
        &pool,
        &sender_vk,
        &sender_addr,
        tip,
    )?;
    let taker = match &reserve {
        Some(reserve) => {
            let taker = super::make_intent::plan_offer_from_pool(
                chain_id,
                crypto_provider,
                complement,
                &pool,
                Some(reserve),
                vault_path,
            )?;
            if let Some(reg) = registration_fee(
                crypto_provider,
                &maker,
                &taker,
                complement.intent_segment,
                tip,
                &ledger_params,
            )? {
                return Ok((taker, Some(MergeFee::Registration(Box::new(reg)))));
            }
            taker.without_reserve(chain_id, crypto_provider, complement, &pool)?
        }
        None => super::make_intent::plan_offer_from_pool(
            chain_id,
            crypto_provider,
            complement,
            &pool,
            None,
            vault_path,
        )?,
    };
    let spend = spend_fee(
        chain_id,
        crypto_provider,
        &maker,
        &taker,
        complement.intent_segment,
        &indexer_url,
        &ledger_params,
        tip,
        vault_path,
    )
    .map_err(|e| {
        if !e.to_string().contains("insufficient DUST") {
            return e;
        }
        let registration = if reserve.is_some() {
            "a registration of its unregistered NIGHT cannot pay the merged fee either"
        } else {
            "it holds no unregistered NIGHT to pay the merged fee by registration instead"
        };
        std::io::Error::other(format!(
            "{e}: {registration}; wait for the wallet's DUST to accrue before completing the swap"
        ))
    })?;
    Ok((taker, Some(MergeFee::Spend(Box::new(spend)))))
}

/// A generationless registration paying the merged fee from the DUST the unregistered NIGHT in the
/// taker's half has generated, sized against the half mock-proven; `None` when that NIGHT cannot cover
/// it (see [`crate::balance_tx::size_merge_registration_fee`]).
fn registration_fee(
    crypto_provider: &MidnightCryptoProvider,
    maker: &TxSealed,
    taker: &OfferPlan,
    taker_seg: u16,
    tip: Timestamp,
    ledger_params: &midnight_ledger::structure::LedgerParameters,
) -> Result<Option<crate::balance_tx::MergeRegistrationFee>, std::io::Error> {
    let taker_base = taker.mock_proven(crypto_provider)?;
    crate::balance_tx::size_merge_registration_fee(
        maker,
        &taker_base,
        taker_seg,
        taker.spent(),
        crypto_provider
            .dust_public_key()
            .map_err(|e| std::io::Error::other(e.to_string()))?,
        crypto_provider
            .unshielded_verifying_key()
            .map_err(|e| std::io::Error::other(e.to_string()))?,
        tip,
        ledger_params,
    )
}

/// A spend of the taker's DUST paying the merged fee, sized against the half mock-proven. The section
/// rides the taker's complement intent and is proved against that intent's binding commitment, so the
/// two stay bound together through the merge.
#[allow(clippy::too_many_arguments)]
fn spend_fee(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    maker: &TxSealed,
    taker: &OfferPlan,
    taker_seg: u16,
    indexer_url: &str,
    ledger_params: &midnight_ledger::structure::LedgerParameters,
    tip: Timestamp,
    vault_path: Option<&Path>,
) -> Result<crate::balance_tx::MergeDustFee, std::io::Error> {
    let taker_base = taker.mock_proven(crypto_provider)?;
    let binding_commitment = taker_base
        .intents
        .get(&taker_seg)
        .ok_or_else(|| std::io::Error::other("taker complement missing its intent segment"))?
        .deref()
        .binding_commitment;
    let scope = crate::wallet::signing_scope(chain_id, vault_path);
    crate::balance_tx::size_merge_dust_fee(
        maker,
        &taker_base,
        taker_seg,
        binding_commitment,
        crypto_provider,
        tip,
        ledger_params,
        indexer_url,
        &scope,
    )
}

/// Authorize the sealed-maker merge: prove the planned taker half (its frame, then the shielded spends
/// of the coins it planned), prove the planned DUST spend into its complement intent, and return a
/// [merge envelope](ows_signer::chains::wrap_merge_envelope) of the (proven, unsealed) taker half plus
/// the sealed maker. Nothing is re-synced, re-selected or re-priced. The sign pipeline then signs the
/// taker's own inputs, seals it, and `Transaction::merge`s it onto the maker in
/// `encode_signed_transaction` — so the taker is signed before it is sealed, and both halves are sealed
/// for the merge, whose summed in-the-clear `binding_randomness` cancels the imbalances into a balanced,
/// submittable whole.
///
/// The maker never pays fees (`makeIntent` is imbalanced by design), so on a live-DUST chain the taker
/// funds the merged tx's fee, with a registration of its NIGHT or from its own dust. With `pay_fees` off
/// (or a fee-less chain) the merged tx is value-balanced but fee-less, and a live-DUST network rejects
/// the submit.
pub(super) fn authorize_merge(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    merge: MergePlan,
    vault_path: Option<&Path>,
) -> Result<Vec<u8>, std::io::Error> {
    let MergePlan {
        maker_tx,
        complement,
        taker,
        fee,
    } = merge;
    // The taker's imbalanced complementary half rides a segment disjoint from the maker's (picked in
    // `complement_from_balance`); that intent carries the fee section.
    let taker_seg = complement.intent_segment;
    let mut taker_base = taker.realize(chain_id, crypto_provider, vault_path)?;
    if let Some(fee) = fee {
        attach_merge_fee(
            chain_id,
            crypto_provider,
            &mut taker_base,
            taker_seg,
            fee,
            vault_path,
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
        &maker_tx,
    ))
}

/// The wallet-relative effects a sealed-maker MERGE will have — the taker's own half **plus** the merged
/// DUST fee it funds — all in the transaction's guaranteed section (segment 0): the taker's coins settle
/// guaranteed just like a plain makeIntent (see [`super::make_intent::GUARANTEED_SEGMENT`]), and the fee
/// is a guaranteed cost. The token movement is request-derived from the taker's
/// [complement](sealed_maker_complement), exactly as a plain makeIntent; the NIGHT coin a fee
/// registration draws on returns whole, so it moves nothing. A fee paid by a DUST spend is the one
/// [`plan_merge`] sized and [`authorize_merge`] pays, folded in as a DUST outflow so a `sum(|diff|)` cap
/// at the policy seam sees the burn.
pub(super) fn merge_segment_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    merge: &MergePlan,
) -> Result<Vec<crate::balance_tx::SegmentEffects>, std::io::Error> {
    let mut effects =
        super::make_intent::request_effects(chain_id, crypto_provider, &merge.complement)?;
    if let Some(fee) = &merge.fee {
        let addresses = crypto_provider
            .addresses(&MidnightNetwork::from_chain_id(chain_id))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if let Some(effect) =
            crate::balance_tx::dust_outflow_effect(addresses.dust, fee.dust_outflow())
        {
            effects.push(effect);
        }
    }
    Ok(crate::balance_tx::single_segment(
        super::make_intent::GUARANTEED_SEGMENT,
        effects,
    ))
}

/// Splice the planned fee section into the taker's complement intent (at `dust_seg`) before sealing,
/// with the TTL the fee was sized for: a registration as planned, a DUST spend once the signer has
/// proved it ([`MidnightCryptoProvider::authorize_dust`]). A spend is bound to the intent's binding
/// commitment, and either section was sized for the planned half only, so a half with another binding
/// commitment is refused.
fn attach_merge_fee(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    taker_base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_seg: u16,
    fee: MergeFee,
    vault_path: Option<&Path>,
) -> Result<(), std::io::Error> {
    let mut intent = taker_base
        .intents
        .get(&dust_seg)
        .ok_or_else(|| std::io::Error::other("taker half missing the complement intent segment"))?
        .deref()
        .clone();
    if intent.binding_commitment != fee.binding_commitment() {
        return Err(std::io::Error::other(
            "the taker half is not the one its DUST fee was planned for; refusing to sign it",
        ));
    }
    let (dust_actions, intent_ttl) = match fee {
        MergeFee::Registration(reg) => (reg.dust_actions, reg.intent_ttl),
        MergeFee::Spend(spend) => {
            let prover = crate::balance_tx::midnight_prover(chain_id, vault_path)?;
            let dust_actions = crate::block_on(crypto_provider.authorize_dust(
                &spend.dust_state,
                &spend.plan,
                &spend.ledger_params,
                prover,
            ))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
            (dust_actions, spend.plan.intent_ttl)
        }
    };

    // The section's fee window is anchored at the planned `dust_ctime`; the intent's TTL follows it.
    intent.dust_actions = Some(Sp::new(dust_actions));
    intent.ttl = intent_ttl;
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
        // The fixture only gives or only wants, which the taker path refuses (MIP-0006), so the
        // negation is checked on the balance itself.
        let Transaction::Standard(base) = &tx else {
            panic!("a standard transaction");
        };
        let segments: BTreeSet<u16> = base.intents.iter().map(|p| *p.deref().0.deref()).collect();
        let req = complement_from_balance(
            tx.balance(None).unwrap(),
            &segments,
            "taker_unshielded",
            "taker_shielded",
        )
        .unwrap();
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

    fn provider() -> MidnightCryptoProvider {
        let mut credential = b"MNK1".to_vec();
        credential.extend_from_slice(&[0x11; 96]);
        ows_signer::chains::MidnightSigner::mainnet()
            .crypto_provider(&ows_signer::SecretBytes::new(credential))
            .unwrap()
    }

    /// The real preprod maker, the taker's complement of it for the [`provider`]'s wallet, and a taker
    /// half planned over `pool` with the wallet's fee-registration reserve, as of `tip`.
    fn registration_merge(
        pool: &[crate::UnshieldedUtxo],
        tip: Timestamp,
    ) -> (Vec<u8>, TxSealed, MakeIntentRequest, OfferPlan) {
        let chain = "midnight:preprod";
        let provider = provider();
        let addresses = provider
            .addresses(&MidnightNetwork::from_chain_id(chain))
            .unwrap();
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        let maker_bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let mut r: &[u8] = &maker_bytes;
        let maker: TxSealed = tagged_deserialize(&mut r).unwrap();
        let Transaction::Standard(base) = &maker else {
            panic!("a standard transaction");
        };
        let segments: BTreeSet<u16> = base.intents.iter().map(|p| *p.deref().0.deref()).collect();
        let complement = complement_from_balance(
            maker.balance(None).unwrap(),
            &segments,
            &addresses.unshielded,
            &addresses.shielded,
        )
        .unwrap();
        let reserve = crate::balance_tx::reserve_for_merge_fee_registration(
            pool,
            &provider.unshielded_verifying_key().unwrap(),
            &addresses.unshielded,
            tip,
        )
        .unwrap();
        let taker = super::super::make_intent::plan_offer_from_pool(
            chain,
            &provider,
            &complement,
            pool,
            reserve.as_ref(),
            None,
        )
        .unwrap();
        (maker_bytes, maker, complement, taker)
    }

    /// A NIGHT coin of the [`provider`]'s wallet on preprod that was never registered and has long
    /// since generated all the DUST it can.
    fn unregistered_coin() -> crate::UnshieldedUtxo {
        crate::UnshieldedUtxo {
            token_type: "00".repeat(32),
            value: 1_000 * midnight_ledger::structure::STARS_PER_NIGHT,
            intent_hash: hex::encode([9u8; 32]),
            output_index: 0,
            owner: provider()
                .addresses(&MidnightNetwork::from_chain_id("midnight:preprod"))
                .unwrap()
                .unshielded,
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    /// A taker whose NIGHT was never registered, and that holds no DUST, pays the merged fee with a
    /// generationless registration of a NIGHT coin its half spends and returns whole. The policy pass
    /// sees how: a registration fee, the registration the taker signs, and no DUST leaving the wallet.
    ///
    /// The fixture swaps NIGHT alone, and a merge that small falls under the node's time-to-dismiss
    /// floor with any fee section (see the next test), so the floor is raised here to size the
    /// registration on its own.
    #[test]
    fn a_taker_holding_only_unregistered_night_pays_the_merge_fee_by_registration() {
        let chain = "midnight:preprod";
        let provider = provider();
        let addresses = provider
            .addresses(&MidnightNetwork::from_chain_id(chain))
            .unwrap();
        let vk = provider.unshielded_verifying_key().unwrap();
        let coin = unregistered_coin();
        let tip = Timestamp::from_secs(10_000_000);
        let (maker_bytes, maker, complement, taker) =
            registration_merge(std::slice::from_ref(&coin), tip);
        assert_eq!(taker.spent(), std::slice::from_ref(&coin));

        let seg = complement.intent_segment;
        let taker_base = taker.mock_proven(&provider).unwrap();
        let offer = taker_base
            .intents
            .get(&seg)
            .unwrap()
            .guaranteed_unshielded_offer
            .clone()
            .unwrap();
        let spent: Vec<u128> = offer.inputs.iter_deref().map(|i| i.value).collect();
        assert_eq!(spent, vec![coin.value]);
        assert!(offer
            .outputs
            .iter_deref()
            .any(|o| o.value == coin.value && o.owner == UserAddress::from(vk.clone())));

        let mut params = midnight_ledger::structure::INITIAL_PARAMETERS;
        params.limits.min_time_to_dismiss = params.limits.min_time_to_dismiss * 100usize;
        let fee = registration_fee(&provider, &maker, &taker, seg, tip, &params)
            .unwrap()
            .expect("the coin's generated DUST covers the merged fee");
        let registration = fee.dust_actions.registrations.iter_deref().next().unwrap();
        assert_eq!(registration.night_key, vk);
        assert_eq!(
            registration.dust_address.as_deref(),
            Some(&provider.dust_public_key().unwrap())
        );
        let allow = fee.allow_fee_payment();

        let plan = ConnectorPlan::BalanceSealedMerge(Box::new(MergePlan {
            maker_tx: maker_bytes,
            complement,
            taker,
            fee: Some(MergeFee::Registration(Box::new(fee))),
        }));
        let context = plan.policy_context(chain, &provider).unwrap();
        assert_eq!(
            context["fee"],
            serde_json::json!({ "mode": "registration", "dust_burned": allow.to_string() })
        );
        assert_eq!(context["dust_registrations"].as_array().unwrap().len(), 1);
        assert_eq!(context["dust_registrations"][0]["intent_id"], seg);
        assert_eq!(context["dust_registrations"][0]["carried"], false);
        assert_eq!(
            context["dust_registrations"][0]["dust_address"],
            addresses.dust
        );
        let effects = &context["segment_effects"][0]["effects"];
        assert_eq!(effects.as_array().unwrap().len(), 1, "no DUST outflow");
        assert_eq!(effects[0]["address"], addresses.unshielded);
    }

    /// A registration that cannot pay the merged fee declines rather than failing the merge, so the
    /// taker falls back to a DUST spend: under the real time-to-dismiss floor the NIGHT-only fixture
    /// cannot carry one, and a coin that generated nothing yet has no DUST to give.
    #[test]
    fn a_registration_that_cannot_pay_the_merge_fee_declines() {
        let tip = Timestamp::from_secs(10_000_000);
        let (_, maker, complement, taker) =
            registration_merge(std::slice::from_ref(&unregistered_coin()), tip);
        let declined = registration_fee(
            &provider(),
            &maker,
            &taker,
            complement.intent_segment,
            tip,
            &midnight_ledger::structure::INITIAL_PARAMETERS,
        )
        .unwrap();
        assert!(declined.is_none(), "the fixture is under the floor");

        let fresh = crate::UnshieldedUtxo {
            ctime_unix_secs: Some(10_000_000),
            ..unregistered_coin()
        };
        let (_, maker, complement, taker) = registration_merge(std::slice::from_ref(&fresh), tip);
        let mut params = midnight_ledger::structure::INITIAL_PARAMETERS;
        params.limits.min_time_to_dismiss = params.limits.min_time_to_dismiss * 100usize;
        let declined = registration_fee(
            &provider(),
            &maker,
            &taker,
            complement.intent_segment,
            tip,
            &params,
        )
        .unwrap();
        assert!(
            declined.is_none(),
            "a coin born at the tip has generated no DUST"
        );

        // The spend that pays instead does not carry the reserved coin, which would only add cost.
        let pool = [fresh];
        let taker = taker
            .without_reserve("midnight:preprod", &provider(), &complement, &pool)
            .unwrap();
        assert!(taker.spent().is_empty());
    }

    #[test]
    fn contracts_of_a_real_sealed_maker_are_read_from_its_intents() {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex");
        let hex_str = hex_str.trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();

        // The fixture is a plain token swap, so it names no contract — what matters here is that a
        // sealed maker's actions are readable at all, i.e. the seam reports `contracts` for a merge
        // instead of failing to parse the maker it already balances against.
        let wallet = UserAddress(HashOutput([0; 32]));
        assert_eq!(maker_contracts(&bytes, &wallet).unwrap(), Vec::new());
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
    fn rejects_an_unknown_option() {
        let err = parse_balance_sealed_json(r#"{"tx":"00","options":{"payfees":false}}"#)
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{err}");
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
            sealed_maker_complement(
                "midnight:preview",
                &sealed(maker),
                "taker_unshielded",
                "taker_shielded",
            )
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

        /// MIP-0006: an offer that only gives, or only wants, is refused whatever form it arrives in.
        #[test]
        fn refuses_a_one_sided_maker() {
            for (maker, what) in [
                (
                    maker(offer(vec![give()], vec![change()]), None),
                    "give-only",
                ),
                (maker(offer(vec![], vec![want()]), None), "want-only"),
            ] {
                let e = complement(maker).expect_err(what);
                assert!(e.to_string().contains("one-sided"), "{what}: {e}");
            }
        }

        #[test]
        fn refuses_a_maker_for_another_network() {
            let mut other = maker(offer(vec![give()], vec![change(), want()]), None);
            other.network_id = "mainnet".to_string();
            let e = complement(other).expect_err("a mainnet maker on preview");
            assert!(e.to_string().contains("network id"), "{e}");
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

        /// A taker whose key is not the maker's, so its movement is told apart from the maker's.
        fn taker() -> MidnightCryptoProvider {
            let mut credential = b"MNK1".to_vec();
            credential.extend_from_slice(&[0x44; 32]);
            credential.extend_from_slice(&[0x55; 32]);
            credential.extend_from_slice(&[0x66; 32]);
            ows_signer::chains::MidnightSigner::preview()
                .crypto_provider(&ows_signer::SecretBytes::new(credential))
                .unwrap()
        }

        /// The taker's half of a merge moves exactly the complement its effects are derived from, and
        /// completes the maker. Built with the planner's own coin selection, it nets per token to the
        /// request-derived effects the policy pass gates on, also when it spends a NIGHT coin to back a
        /// fee registration, which returns whole, and with the maker it leaves no token imbalanced, so
        /// the merge moves nothing the policy did not see.
        #[test]
        fn the_taker_half_moves_its_complement_and_completes_the_maker() {
            const CHAIN: &str = "midnight:preview";
            let taker = taker();
            let own = taker
                .addresses(&MidnightNetwork::from_chain_id(CHAIN))
                .unwrap();
            let maker_tx = sealed(maker(offer(vec![give()], vec![change(), want()]), None));
            let complement =
                sealed_maker_complement(CHAIN, &maker_tx, &own.unshielded, &own.shielded).unwrap();
            // The taker pays the 50 it is asked for from an 80 coin, and gets 30 back.
            let pool = [crate::UnshieldedUtxo {
                token_type: hex::encode([0x22; 32]),
                value: 80,
                intent_hash: hex::encode([9; 32]),
                output_index: 0,
                owner: own.unshielded.clone(),
                ctime_unix_secs: Some(1_000),
                registered_for_dust_generation: false,
            }];
            let half = crate::dapp_connector::make_intent::plan_offer_from_pool(
                CHAIN,
                &taker,
                &complement,
                &pool,
                None,
                None,
            )
            .unwrap();
            let built = half.mock_proven(&taker).unwrap();
            let declared =
                crate::dapp_connector::make_intent::request_effects(CHAIN, &taker, &complement)
                    .unwrap();
            let reserve = crate::UnshieldedUtxo {
                token_type: "00".repeat(32),
                value: 5_000,
                intent_hash: hex::encode([8; 32]),
                ..pool[0].clone()
            };
            let reserving = crate::dapp_connector::make_intent::plan_offer_from_pool(
                CHAIN,
                &taker,
                &complement,
                &pool,
                Some(&reserve),
                None,
            )
            .unwrap();
            assert_eq!(reserving.spent().len(), 2);
            assert_eq!(
                crate::dapp_connector::make_intent::built_movement(
                    CHAIN,
                    &taker,
                    &reserving.mock_proven(&taker).unwrap()
                ),
                declared
            );

            let merge = MergePlan {
                maker_tx: maker_tx.clone(),
                complement,
                taker: half,
                fee: None,
            };
            assert_eq!(
                merge_segment_effects(CHAIN, &taker, &merge).unwrap(),
                crate::balance_tx::single_segment(
                    0,
                    crate::dapp_connector::make_intent::built_movement(CHAIN, &taker, &built)
                )
            );

            let mut r: &[u8] = &maker_tx;
            let maker: TxSealed = tagged_deserialize(&mut r).unwrap();
            let mut net: BTreeMap<LedgerTokenType, i128> = BTreeMap::new();
            let balances = maker
                .balance(None)
                .unwrap()
                .into_iter()
                .chain(Transaction::Standard(built).balance(None).unwrap());
            for ((token, _segment), balance) in balances {
                if token != LedgerTokenType::Dust {
                    *net.entry(token).or_default() += balance;
                }
            }
            assert!(!net.is_empty());
            assert!(net.values().all(|balance| *balance == 0), "{net:?}");
        }

        fn plan_maker(maker_tx: &[u8]) -> Result<ConnectorPlan, std::io::Error> {
            let json = serde_json::json!({
                "method": "balanceSealedTransaction",
                "makerTx": hex::encode(maker_tx),
            })
            .to_string();
            plan("midnight:preview", &provider(), &json, None)
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
