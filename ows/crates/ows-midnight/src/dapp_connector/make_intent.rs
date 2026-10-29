//! DApp Connector `makeIntent`.
//!
//! `makeIntent(desiredInputs, desiredOutputs, options)` asks the wallet to build a **single-segment,
//! deliberately imbalanced** swap-offer intent — the maker side of a swap. The maker contributes real
//! inputs and declares the outputs it wants; a counterparty completes and balances it later
//! (`balanceSealedTransaction`). Because it is imbalanced by design, `makeIntent` does **not** run the
//! balancing tail: the plan picks the maker's coins and builds its inputs + outputs, and `authorize`
//! proves them and returns the signable bytes for the downstream sign/seal.
//!
//! Scope: unshielded and shielded inputs (whole coins, with change back to the maker) and
//! unshielded/shielded outputs. The maker declares how much of a token it contributes; the wallet spends
//! whole coins covering that amount and returns the excess as change to the maker — so a shielded input
//! contributes exactly its declared value regardless of what token the offer wants back. The shielded
//! spend witnesses are built and proved in the signer ([`MidnightCryptoProvider::authorize_shielded`])
//! and the proved fragment is merged into the proved maker frame, so the bearer preimage never leaves the
//! signer.
//!
//! The offer's **expiry** is load-bearing in a way it is not for the other methods. `Intent.ttl` sits
//! inside the seal cover, and makeIntent runs no balancing tail, so nothing after this module can move
//! it — not the taker, not a service relaying the offer. It is also the maker's only unilateral way out:
//! a sealed offer is a bearer artifact, cancellable only by letting it expire or by double-spending one
//! of its inputs. Left at the wallet default it is the widest window the ledger allows, which is a free
//! option written against the maker's quoted price; `options.ttl` lets a maker that re-quotes often say
//! how long its price stands.
//!
//! Both the shielded and unshielded legs ride the transaction's **guaranteed section** (segment 0),
//! and — unlike `makeTransfer` — a swap keeps its NIGHT there rather than steering it to a fallible
//! segment. The ledger balances value **per segment**: every `(token, segment)` cell must net on its
//! own (a negative cell is `BalanceCheckOverspend`), and two parties' intents cannot share a segment
//! (`IntentSegmentIdCollision`). A swap is inherently cross-party, so the maker's unshielded spend and
//! the taker's unshielded receipt can only meet — and net — in segment 0, the one intent-free shared
//! section; steered to a fallible segment they would land in different segments and overspend.
//! (`makeTransfer` *can* ride a fallible segment precisely because it is single-party self-funded and
//! nets within its own segment.) Only a pure shielded↔shielded swap could anchor a fallible segment —
//! its zswap legs pool in `fallible_coins` — but that saves nothing (only the guaranteed *unshielded*
//! offer loads the segment-0 `time_to_dismiss` budget) and weakens the swap's all-or-nothing atomicity,
//! so makeIntent keeps every leg guaranteed. The maker's intent still keys at a fallible segment
//! (`intentId`); only the coins settle guaranteed. See [`GUARANTEED_SEGMENT`].

use std::collections::BTreeMap;
use std::ops::Deref as _;
use std::path::Path;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Info as CoinInfo, QualifiedInfo, ShieldedTokenType, UserAddress, NIGHT,
};
use midnight_ledger::structure::{
    Intent, ProofMarker, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer,
    UtxoOutput, UtxoSpend,
};
use midnight_serialize::tagged_serialize;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_core::sync_cache::SyncCacheScope;
use ows_signer::chains::{
    MidnightCryptoProvider, MidnightNetwork, MidnightSigner, ShieldedSpendPlan,
};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::Deserialize;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::ProofPreimage;

use super::build::{
    decode_shielded_recipient, decode_unshielded_recipient, default_intent_ttl, deserialize_u128,
    effects_from_movements, err, max_ttl_secs, mock_prove_unsealed, now_secs, prove_preimage,
    wire_type_to_shielded, wire_type_to_unshielded, DesiredOutput, Movement, PreimageTx,
    TransferKind,
};
use crate::parse_token_type;
use ows_core::policy::TransactionEffect;

/// The segment a maker's intent keys at when the request omits `intentId`. The spec's own guidance for
/// picking one: segment 1 "ensures no transaction merging will result in actions executed before created
/// intent in the same transaction".
const DEFAULT_INTENT_SEGMENT: u16 = 1;

/// Segment 0 is the transaction's guaranteed section. A swap offer's shielded coins ride it — like
/// `makeTransfer` places its own — so both legs of the swap sit in **one** segment. The ledger
/// applies each segment atomically (a segment-0 failure reverts the whole tx; a fallible segment fails
/// alone), so a swap split across the guaranteed and a fallible section could settle one leg and drop
/// the other. The intent itself still keys at a fallible segment (`intentId`); only the coins move.
/// The merge path reuses this for the taker complement's own coins, which settle guaranteed the same way.
pub(super) const GUARANTEED_SEGMENT: u16 = 0;

/// The maker's unshielded offer, if it has one, and the coins it spends.
type OfferAndCoins = (
    Option<UnshieldedOffer<MnSig, InMemoryDB>>,
    Vec<crate::UnshieldedUtxo>,
);

/// The inputs selected for the maker's requested rows, their change, and the coins they spend.
type SelectedInputs = (Vec<UtxoSpend>, Vec<UtxoOutput>, Vec<crate::UnshieldedUtxo>);

/// One input the maker contributes: a `value` of `token_type` in `kind`'s domain (no recipient — the
/// maker spends its own coins).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesiredInput {
    pub kind: TransferKind,
    #[serde(
        rename = "type",
        deserialize_with = "super::build::deserialize_token_type"
    )]
    pub token_type: String,
    #[serde(deserialize_with = "deserialize_u128")]
    pub value: u128,
}

/// A parsed `makeIntent` request: the maker's inputs and desired outputs, the resolved intent segment
/// (`intentId`, with `"random"` already drawn), and the offer's expiry. `ttl` is `None` when the request
/// names no expiry, leaving the wallet's [`default_intent_ttl`]. `payFees` is not carried: a maker offer
/// is fee-free by construction here, and a request asking otherwise is rejected at parse.
#[derive(Debug, Clone)]
pub struct MakeIntentRequest {
    pub desired_inputs: Vec<DesiredInput>,
    pub desired_outputs: Vec<DesiredOutput>,
    pub intent_segment: u16,
    pub ttl: Option<Timestamp>,
}

/// A `makeIntent` planned for the policy seam: the request, with its offer's expiry fixed, and the offer
/// decided, its coins picked. The expiry is the request's own `ttl`, or the wallet default taken when the
/// plan is made, so the instant the policy pass reads is the one that gets sealed; the coins are picked
/// once, so the ones the policy pass allowed are the ones that get spent.
pub struct IntentPlan {
    request: MakeIntentRequest,
    offer: OfferPlan,
    ttl: Timestamp,
    ttl_is_default: bool,
}

/// Plan a `makeIntent`: fix the offer's expiry and decide the offer, picking the coins its inputs spend
/// from the wallet's synced coin set. The effects still come from the request, which the picked coins
/// net to exactly: whole coins are spent and the excess returns to the maker.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    request: MakeIntentRequest,
    vault_path: Option<&Path>,
) -> Result<IntentPlan, std::io::Error> {
    let pool = unshielded_pool(
        chain_id,
        crypto_provider,
        &request.desired_inputs,
        vault_path,
    )?;
    plan_from_pool(chain_id, crypto_provider, request, &pool, vault_path)
}

fn plan_from_pool(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    request: MakeIntentRequest,
    pool: &[crate::UnshieldedUtxo],
    vault_path: Option<&Path>,
) -> Result<IntentPlan, std::io::Error> {
    let ttl_is_default = request.ttl.is_none();
    let ttl = request.ttl.unwrap_or_else(default_intent_ttl);
    let request = MakeIntentRequest {
        ttl: Some(ttl),
        ..request
    };
    let offer = plan_offer_from_pool(chain_id, crypto_provider, &request, pool, None, vault_path)?;
    Ok(IntentPlan {
        request,
        offer,
        ttl,
        ttl_is_default,
    })
}

impl IntentPlan {
    pub(super) fn request(&self) -> &MakeIntentRequest {
        &self.request
    }

    /// The offer the maker seals: the intent it keys at and when it expires.
    pub(super) fn offer_context(&self) -> crate::policy_context::OfferContext {
        crate::policy_context::OfferContext {
            intent_id: self.request.intent_segment,
            ttl: self.ttl.to_secs(),
            ttl_is_default: self.ttl_is_default,
        }
    }
}

/// The `options` bag of a `makeIntent` request: the connector spec's `intentId` and `payFees`, plus the
/// `ttl` extension. Any other key is refused, so a misspelled `ttl` cannot quietly leave a sealed offer
/// on the default expiry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MakeIntentOptions {
    intent_id: Option<IntentIdJson>,
    pay_fees: Option<bool>,
    ttl: Option<u64>,
}

/// The spec's `intentId: number | "random"` — the segment the maker's intent keys at, or a request that
/// the wallet pick one.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IntentIdJson {
    Segment(u64),
    Keyword(String),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MakeIntentJson {
    #[serde(default)]
    desired_inputs: Vec<DesiredInput>,
    #[serde(default)]
    desired_outputs: Vec<DesiredOutput>,
    #[serde(default)]
    options: Option<MakeIntentOptions>,
}

/// Parse a stringified DApp Connector `makeIntent` request. `options.intentId` names the maker intent's
/// segment (see [`resolve_intent_segment`]) and defaults to segment 1; `options.payFees` may only ask for
/// the fee-free maker offer this wallet builds (see [`check_pay_fees`]); `options.ttl` defaults to the
/// wallet's own [`default_intent_ttl`] and must name an instant the ledger will still accept (see
/// [`parse_intent_ttl`]).
pub fn parse_make_intent_json(json: &str) -> Result<MakeIntentRequest, std::io::Error> {
    let req: MakeIntentJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid makeIntent request JSON: {e}")))?;
    if req.desired_inputs.is_empty() && req.desired_outputs.is_empty() {
        return Err(std::io::Error::other(
            "makeIntent requires at least one desired input or output",
        ));
    }
    let (intent_id, pay_fees, ttl) = match req.options {
        Some(o) => (o.intent_id, o.pay_fees, o.ttl),
        None => (None, None, None),
    };
    check_pay_fees(pay_fees)?;
    Ok(MakeIntentRequest {
        desired_inputs: req.desired_inputs,
        desired_outputs: req.desired_outputs,
        intent_segment: resolve_intent_segment(intent_id)?,
        ttl: parse_intent_ttl(ttl, now_secs())?,
    })
}

/// Resolve the spec's `intentId` to the segment the maker's intent keys at: a number is taken as given,
/// `"random"` is drawn by the wallet (the spec's suggested mode for swaps), and an absent option falls
/// back to [`DEFAULT_INTENT_SEGMENT`].
///
/// Two bounds are the ledger's. Segment ids are 16-bit, and segment 0 is the guaranteed section, where an
/// intent is rejected outright (`IntentAtGuaranteedSegmentId`, surfaced by the node as `Custom error:
/// 167`) — the spec's "within ledger limitations". Rejecting here beats building an offer the node will
/// throw away.
fn resolve_intent_segment(intent_id: Option<IntentIdJson>) -> Result<u16, std::io::Error> {
    match intent_id {
        None => Ok(DEFAULT_INTENT_SEGMENT),
        Some(IntentIdJson::Segment(0)) => Err(std::io::Error::other(
            "makeIntent options.intentId must be >= 1: segment 0 is the guaranteed section, where the ledger rejects an intent",
        )),
        Some(IntentIdJson::Segment(n)) => u16::try_from(n).map_err(|_| {
            std::io::Error::other(format!(
                "makeIntent options.intentId {n} is out of range: a segment id is at most {}",
                u16::MAX
            ))
        }),
        // Any fallible segment will do for a lone maker intent, so draw from the whole space rather than
        // the low end: a wide draw is what keeps two independently-built intents from colliding
        // (`IntentSegmentIdCollision`) when a taker merges its own into the same transaction.
        Some(IntentIdJson::Keyword(k)) if k == "random" => Ok(OsRng.gen_range(1..=u16::MAX)),
        Some(IntentIdJson::Keyword(k)) => Err(std::io::Error::other(format!(
            "makeIntent options.intentId must be a segment number or \"random\", not \"{k}\""
        ))),
    }
}

/// Reject a request asking the wallet to pay the maker's fees. `makeIntent` here builds a fee-free maker
/// offer — the taker funds the DUST when it completes and balances the swap — so `payFees: true` is a
/// thing this wallet cannot do, and saying so beats returning an offer that silently does the opposite of
/// what was asked. An absent option is read as the fee-free offer, which is also what the reference wallet
/// SDK's `initSwap` defaults to.
fn check_pay_fees(pay_fees: Option<bool>) -> Result<(), std::io::Error> {
    if pay_fees == Some(true) {
        return Err(std::io::Error::other(
            "makeIntent options.payFees: true is not supported: a maker offer is imbalanced and fee-free, and the taker funds the DUST fee when it completes the swap",
        ));
    }
    Ok(())
}

/// Validate a requested expiry (Unix epoch seconds) against the window the ledger will accept for an
/// offer built *now*. Both bounds are the ledger's own, measured against the block the offer lands in
/// (`tblock`): it rejects `ttl < tblock` (`IntentTtlExpired`) and `ttl > tblock + global_ttl`
/// (`IntentTtlTooFarInFuture`). `tblock` is unknowable at build time but is never earlier than now, so
/// `now` is the conservative stand-in — an offer inside this window is acceptable whenever it settles,
/// and one outside it is rejected at build rather than after the maker has paid to prove it.
fn parse_intent_ttl(ttl: Option<u64>, now: u64) -> Result<Option<Timestamp>, std::io::Error> {
    let Some(ttl) = ttl else {
        return Ok(None);
    };
    if ttl <= now {
        return Err(std::io::Error::other(format!(
            "makeIntent options.ttl {ttl} is not in the future (now {now}): the offer would be born expired"
        )));
    }
    let max = now.saturating_add(max_ttl_secs());
    if ttl > max {
        return Err(std::io::Error::other(format!(
            "makeIntent options.ttl {ttl} is further ahead than the ledger's global_ttl ({}s) allows: at most {max}",
            max_ttl_secs()
        )));
    }
    Ok(Some(Timestamp::from_secs(ttl)))
}

/// The wallet-relative effects a `makeIntent` maker offer will have, derived from the request alone: the
/// maker contributes each desired input (outflow), and receives each desired output routed back to its
/// own address (inflow) — an output to some other recipient is not the maker's movement. The policy seam
/// gates on this before [`authorize`] proves anything.
pub(super) fn request_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<Vec<TransactionEffect>, std::io::Error> {
    let addresses = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?;
    let mut movements = Vec::new();
    for i in &req.desired_inputs {
        movements.push(Movement {
            kind: i.kind,
            token_type: &i.token_type,
            value: -crate::balance_tx::signed_amount(i.value)?,
        });
    }
    for o in &req.desired_outputs {
        let self_addr = match o.kind {
            TransferKind::Unshielded => &addresses.unshielded,
            TransferKind::Shielded => &addresses.shielded,
        };
        if o.recipient == *self_addr {
            movements.push(Movement {
                kind: o.kind,
                token_type: &o.token_type,
                value: crate::balance_tx::signed_amount(o.value)?,
            });
        }
    }
    effects_from_movements(&addresses, movements)
}

/// The `makeIntent` maker offer's wallet-relative effects as [`request_effects`] computes them, all in
/// the transaction's guaranteed section ([`GUARANTEED_SEGMENT`]): a swap keeps every leg guaranteed — the
/// maker's coins settle in segment 0 even though its intent keys at a fallible `intentId` — so the
/// movement a policy sees is a guaranteed one. An offer that nets nothing yields no segment entry.
pub(super) fn request_segment_effects(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
) -> Result<Vec<crate::balance_tx::SegmentEffects>, std::io::Error> {
    let effects = request_effects(chain_id, crypto_provider, req)?;
    Ok(crate::balance_tx::single_segment(
        GUARANTEED_SEGMENT,
        effects,
    ))
}

/// Prove the planned maker offer and return the signable bytes. Runs **after** the policy seam, and
/// spends exactly the coins the plan picked: nothing is re-synced or re-selected. No balancing: the
/// imbalance is the offer.
pub(super) fn authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    plan: IntentPlan,
    vault_path: Option<&Path>,
) -> Result<Vec<u8>, std::io::Error> {
    let base = plan.offer.realize(chain_id, crypto_provider, vault_path)?;
    let mut out = Vec::new();
    tagged_serialize(&Transaction::Standard(base), &mut out)
        .map_err(|e| err(format!("serialize proven tx: {e}")))?;
    Ok(out)
}

/// A `makeIntent` offer decided but not yet proven: the frame's preimage (the unshielded inputs it
/// picked, with change, and its outputs), the unshielded coins it spends as the indexer reported them,
/// and, when the offer spends shielded coins, the coins picked to fund them.
/// [`mock_proven`](Self::mock_proven) stands in for it before the policy seam, and
/// [`realize`](Self::realize) proves exactly this offer after it, so whatever was sized against the mock
/// still holds.
pub(super) struct OfferPlan {
    frame: PreimageTx,
    spent: Vec<crate::UnshieldedUtxo>,
    funding: Option<crate::balance_tx::ShieldedFundingPlan>,
}

/// The wallet's unshielded coins, fetched from the indexer only when the offer spends any.
fn unshielded_pool(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    inputs: &[DesiredInput],
    vault_path: Option<&Path>,
) -> Result<Vec<crate::UnshieldedUtxo>, std::io::Error> {
    if !inputs.iter().any(|d| d.kind == TransferKind::Unshielded) {
        return Ok(Vec::new());
    }
    wallet_unshielded_pool(chain_id, crypto_provider, vault_path)
}

/// The wallet's unshielded coins, as the indexer of the caller's vault reports them.
pub(super) fn wallet_unshielded_pool(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    vault_path: Option<&Path>,
) -> Result<Vec<crate::UnshieldedUtxo>, std::io::Error> {
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    crate::block_on(crate::get_unshielded_utxos_for_display(
        &crate::wallet::resolve_indexer_url(chain_id, vault_path)?,
        &sender_addr,
        &SyncCacheScope {
            vault_path: vault_path.map(Path::to_path_buf),
            ..Default::default()
        },
    ))
}

/// Decide a maker offer from the wallet's unshielded coins `pool`: pick the coins its unshielded
/// inputs spend and build the frame, and pick the shielded coins its shielded inputs spend. `reserve`
/// is a NIGHT coin to spend as well, balance-neutrally (its whole value returns to the maker), so that a
/// fee registration riding the offer's intent can draw on the DUST it has generated. Inert: nothing is
/// proven or signed.
pub(super) fn plan_offer_from_pool(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
    pool: &[crate::UnshieldedUtxo],
    reserve: Option<&crate::UnshieldedUtxo>,
    vault_path: Option<&Path>,
) -> Result<OfferPlan, std::io::Error> {
    let (frame, spent) = offer_frame(chain_id, crypto_provider, req, pool, reserve)?;
    let shielded_in: Vec<&DesiredInput> = req
        .desired_inputs
        .iter()
        .filter(|d| d.kind == TransferKind::Shielded)
        .collect();
    let funding = if shielded_in.is_empty() {
        None
    } else {
        Some(plan_shielded_input_funding(
            chain_id,
            crypto_provider,
            GUARANTEED_SEGMENT,
            &shielded_in,
            vault_path,
        )?)
    };
    Ok(OfferPlan {
        frame,
        spent,
        funding,
    })
}

/// The frame of a maker offer over the wallet's unshielded coins `pool`, and the coins it spends.
fn offer_frame(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeIntentRequest,
    pool: &[crate::UnshieldedUtxo],
    reserve: Option<&crate::UnshieldedUtxo>,
) -> Result<(PreimageTx, Vec<crate::UnshieldedUtxo>), std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);
    let (unshielded_in, shielded_in): (Vec<_>, Vec<_>) = req
        .desired_inputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);
    build_make_intent_frame(
        chain_id,
        &signer,
        crypto_provider,
        req.intent_segment,
        pool,
        reserve,
        &unshielded_in,
        &unshielded_out,
        &shielded_out,
        !shielded_in.is_empty(),
        req.ttl,
    )
}

impl OfferPlan {
    /// The same offer without a reserved coin: the frame built again from `pool` with nothing reserved,
    /// and the shielded coins kept as they were picked.
    pub(super) fn without_reserve(
        self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
        req: &MakeIntentRequest,
        pool: &[crate::UnshieldedUtxo],
    ) -> Result<OfferPlan, std::io::Error> {
        let (frame, spent) = offer_frame(chain_id, crypto_provider, req, pool, None)?;
        Ok(OfferPlan {
            frame,
            spent,
            funding: self.funding,
        })
    }

    /// The unshielded coins the offer spends, with the block time and DUST registration the indexer
    /// reported for each.
    pub(super) fn spent(&self) -> &[crate::UnshieldedUtxo] {
        &self.spent
    }

    /// The offer **mock-proven**: fixed-size, non-verifying proofs that serialize to the exact length of
    /// the real ones, so a transaction sized against it gets the real fee. No real proving happens, so it
    /// is safe **before** the policy seam; the sealed merge sizes its DUST fee against it.
    pub(super) fn mock_proven(
        &self,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<
        StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
        std::io::Error,
    > {
        // Mock-prove into the *unsealed* proven form: `mock_prove` would seal it, but the merge fee
        // sizing seals the taker itself (once the DUST section is spliced in).
        let Transaction::Standard(base) = mock_prove_unsealed(self.frame.clone())? else {
            return Err(err(
                "mock-proven makeIntent frame is not a Standard transaction",
            ));
        };
        match &self.funding {
            None => Ok(base),
            Some(funding) => {
                crate::balance_tx::splice_mock_shielded_for_sizing(&base, crypto_provider, funding)
            }
        }
    }

    /// Prove the offer for real. Runs **after** the policy seam: the frame (unshielded offer + shielded
    /// outputs) is proved first, then the signer builds and proves the planned shielded spend witnesses
    /// (the bearer preimage is born and consumed there) and the proved fragment is merged in.
    pub(super) fn realize(
        self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
        vault_path: Option<&Path>,
    ) -> Result<
        StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
        std::io::Error,
    > {
        let Transaction::Standard(mut base) = prove_preimage(chain_id, self.frame, vault_path)?
        else {
            return Err(err("makeIntent frame is not a Standard transaction"));
        };
        if let Some(funding) = &self.funding {
            authorize_shielded_inputs(chain_id, crypto_provider, funding, &mut base, vault_path)?;
        }
        Ok(base)
    }
}

/// Construct the `proof-preimage` maker frame: the maker's unshielded inputs (with change back to the
/// maker) + unshielded/shielded outputs, deliberately imbalanced, and the unshielded coins it spends.
/// The intent keys at `segment` (`intentId`), but the shielded outputs ride the guaranteed section (see
/// [`GUARANTEED_SEGMENT`]). Shielded *inputs* are authorized separately, after proving, so
/// `has_shielded_in` keeps the empty-offer guard from firing when the maker's only contribution is
/// shielded inputs.
#[allow(clippy::too_many_arguments)]
fn build_make_intent_frame(
    chain_id: &str,
    signer: &MidnightSigner,
    crypto_provider: &MidnightCryptoProvider,
    segment: u16,
    pool: &[crate::UnshieldedUtxo],
    reserve: Option<&crate::UnshieldedUtxo>,
    unshielded_in: &[&DesiredInput],
    unshielded_out: &[&DesiredOutput],
    shielded_out: &[&DesiredOutput],
    has_shielded_in: bool,
    ttl: Option<Timestamp>,
) -> Result<(PreimageTx, Vec<crate::UnshieldedUtxo>), std::io::Error> {
    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| err(e.to_string()))?;
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    let (unshielded_offer, spent) = build_unshielded_offer(
        signer,
        &sender_addr,
        &sender_vk,
        pool,
        reserve,
        unshielded_in,
        unshielded_out,
    )?;
    let zswap_offer = build_shielded_output_offer(signer, GUARANTEED_SEGMENT, shielded_out)?;
    if unshielded_offer.is_none() && zswap_offer.is_none() && !has_shielded_in {
        return Err(err("makeIntent produced no offer"));
    }

    let mut rng = OsRng;
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: unshielded_offer.map(Sp::new),
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        // Unlike the balancing methods, makeIntent never runs the balancing tail, so nothing downstream
        // re-aligns this TTL to the chain tip — and it is inside the seal cover, so no later holder of
        // the offer can change it either. Whatever is chosen here is the offer's real expiry.
        ttl: ttl.unwrap_or_else(default_intent_ttl),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(segment, intent);
    let (guaranteed_coins, fallible_coins) = place_zswap_offer(GUARANTEED_SEGMENT, zswap_offer);
    let mut stx = StandardTransaction {
        network_id: signer.ledger_network_id().to_string(),
        intents,
        guaranteed_coins,
        fallible_coins,
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    Ok((Transaction::Standard(stx), spent))
}

/// Sync the wallet's shielded coins and select whole coins covering each declared shielded input,
/// returning a fee-sizeable funding plan: the selected spend plan bound to `segment`, plus the synced,
/// merkle-ready coin tree. Picked once per [`OfferPlan`], so its mock and its real proofs spend the same
/// coins.
fn plan_shielded_input_funding(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    segment: u16,
    shielded_in: &[&DesiredInput],
    vault_path: Option<&Path>,
) -> Result<crate::balance_tx::ShieldedFundingPlan, std::io::Error> {
    let deficits = shielded_input_deficits(shielded_in)?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id, vault_path)?;
    let scope = crate::wallet::signing_scope(chain_id, vault_path);
    let block_height = crate::tip_verify::fetch_current_block_height(&indexer_url);
    let synced = crate::block_on(crate::wallet_sync::shielded::sync_wallet(
        &indexer_url,
        crypto_provider,
        &scope,
        block_height,
    ))?;
    let mut tree = synced.zswap;
    crate::wallet_sync::shielded::ensure_shielded_merkle_ready(&mut tree)?;

    let coins: Vec<QualifiedInfo> = tree.coins.iter().map(|(_nul, qci)| *qci.deref()).collect();
    let selection = crate::balance_tx::plan_shielded_inputs(&coins, &deficits)?;
    let plan = ShieldedSpendPlan {
        segment,
        coins: selection.coins,
        change: selection.change_by_token,
    };
    Ok(crate::balance_tx::ShieldedFundingPlan {
        plans: vec![plan],
        tree,
    })
}

/// Authorize the maker's shielded inputs into the already-proved frame: hand the planned coins (from
/// [`plan_shielded_input_funding`]) to [`MidnightCryptoProvider::authorize_shielded`], which builds +
/// proves the spend witnesses and the self-change, both in the guaranteed section (see
/// [`GUARANTEED_SEGMENT`]). The proved fragment is merged into `base`'s guaranteed coins and its Pedersen
/// binding delta folded in (a proved tx can't recompute its own).
fn authorize_shielded_inputs(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    funding: &crate::balance_tx::ShieldedFundingPlan,
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    vault_path: Option<&Path>,
) -> Result<(), std::io::Error> {
    let prover = crate::balance_tx::midnight_prover(chain_id, vault_path)?;
    let authorized =
        crate::block_on(crypto_provider.authorize_shielded(&funding.plans, &funding.tree, prover))
            .map_err(|e| err(e.to_string()))?;

    for (seg, proven_offer) in &authorized.proven {
        crate::balance_tx::place_shielded_fragment(base, *seg, proven_offer)?;
    }
    base.binding_randomness = base.binding_randomness + authorized.binding_delta;
    Ok(())
}

/// Aggregate the declared shielded inputs into one whole-coin deficit per token (summing repeats), so a
/// token's coins are selected once and the change is `selected total − declared total`.
fn shielded_input_deficits(
    inputs: &[&DesiredInput],
) -> Result<Vec<(ShieldedTokenType, u128)>, std::io::Error> {
    let mut by_token: BTreeMap<ShieldedTokenType, u128> = BTreeMap::new();
    for d in inputs {
        if d.value == 0 {
            return Err(err("desired input value must be greater than zero"));
        }
        let token = wire_type_to_shielded(&d.token_type)?;
        let entry = by_token.entry(token).or_insert(0);
        *entry = entry.saturating_add(d.value);
    }
    Ok(by_token.into_iter().collect())
}

/// Route the shielded offer to the segment its outputs were bound to: segment 0 → the guaranteed offer;
/// segment N ≥ 1 → `fallible_coins[N]` (mirrors the ledger's guaranteed/fallible split).
#[allow(clippy::type_complexity)]
fn place_zswap_offer(
    segment: u16,
    offer: Option<ZswapOffer<ProofPreimage, InMemoryDB>>,
) -> (
    Option<Sp<ZswapOffer<ProofPreimage, InMemoryDB>, InMemoryDB>>,
    MnHashMap<u16, ZswapOffer<ProofPreimage, InMemoryDB>, InMemoryDB>,
) {
    match offer {
        None => (None, MnHashMap::new()),
        Some(o) if segment == 0 => (Some(Sp::new(o)), MnHashMap::new()),
        Some(o) => (None, MnHashMap::new().insert(segment, o)),
    }
}

/// Build the maker's unshielded offer: select UTXOs from the wallet's `pool` to cover each input, spend
/// them (returning any whole-coin excess as change back to the maker), spend the `reserve` coin unless a
/// row already does (all of it returning as change), and append the desired unshielded outputs. Returns
/// the offer and the coins it spends.
fn build_unshielded_offer(
    signer: &MidnightSigner,
    sender_addr: &str,
    sender_vk: &VerifyingKey,
    pool: &[crate::UnshieldedUtxo],
    reserve: Option<&crate::UnshieldedUtxo>,
    inputs_requested: &[&DesiredInput],
    outputs_requested: &[&DesiredOutput],
) -> Result<OfferAndCoins, std::io::Error> {
    if inputs_requested.is_empty() && outputs_requested.is_empty() && reserve.is_none() {
        return Ok((None, Vec::new()));
    }

    let mut inputs: Vec<UtxoSpend> = Vec::new();
    let mut outputs: Vec<UtxoOutput> = Vec::new();
    let mut spent: Vec<crate::UnshieldedUtxo> = Vec::new();

    if !inputs_requested.is_empty() || reserve.is_some() {
        let maker = decode_unshielded_recipient(signer, sender_addr)?;
        let (mut selected_inputs, mut change_outputs, selected) =
            select_unshielded_inputs(pool, inputs_requested, sender_addr, sender_vk, maker)?;
        inputs.append(&mut selected_inputs);
        outputs.append(&mut change_outputs);
        spent = selected;
        if let Some(r) = reserve.filter(|r| !spent.contains(r)) {
            inputs.push(UtxoSpend {
                value: r.value,
                owner: crate::balance_tx::resolve_owner_vk(&r.owner, sender_addr, sender_vk)?,
                type_: NIGHT,
                intent_hash: crate::balance_tx::parse_intent_hash_hex(&r.intent_hash)?,
                output_no: u32::try_from(r.output_index)
                    .map_err(|_| err("output index out of range"))?,
            });
            outputs.push(UtxoOutput {
                value: r.value,
                owner: maker,
                type_: NIGHT,
            });
            spent.push(r.clone());
        }
    }

    for d in outputs_requested {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        outputs.push(UtxoOutput {
            value: d.value,
            owner: decode_unshielded_recipient(signer, &d.recipient)?,
            type_: wire_type_to_unshielded(&d.token_type)?,
        });
    }

    inputs.sort();
    outputs.sort();
    let offer = UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    };
    Ok((Some(offer), spent))
}

/// Select the maker's unshielded input coins for each requested input from `utxos`, plus the per-row
/// whole-coin change back to `maker`, and the coins selected.
///
/// A `claimed` set threads across rows so a coin picked for one row is excluded from the next — without
/// it, two rows of the same token both select the same largest coin and the offer double-spends it (the
/// balancer's `build_night_offer` uses the same guard). Pure over `utxos` — no network — so it is unit
/// testable.
fn select_unshielded_inputs(
    utxos: &[crate::UnshieldedUtxo],
    inputs_requested: &[&DesiredInput],
    sender_addr: &str,
    sender_vk: &VerifyingKey,
    maker: UserAddress,
) -> Result<SelectedInputs, std::io::Error> {
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    let mut change: Vec<UtxoOutput> = Vec::new();
    let mut spent: Vec<crate::UnshieldedUtxo> = Vec::new();
    let mut claimed: Vec<(String, i64)> = Vec::new();
    for d in inputs_requested {
        if d.value == 0 {
            return Err(err("desired input value must be greater than zero"));
        }
        let wire = parse_token_type(Some(&d.token_type))?.to_wire_token_type();
        let type_ = wire_type_to_unshielded(&d.token_type)?;
        let available: Vec<crate::UnshieldedUtxo> = utxos
            .iter()
            .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
            .cloned()
            .collect();
        let selected = crate::balance_tx::select_utxos_for_token(
            &available,
            sender_addr,
            sender_vk,
            &wire,
            d.value,
        )?;
        let mut total = 0u128;
        for u in &selected {
            spent.push(u.clone());
            claimed.push((u.intent_hash.clone(), u.output_index));
            total = total.saturating_add(u.value);
            inputs.push(UtxoSpend {
                value: u.value,
                owner: crate::balance_tx::resolve_owner_vk(&u.owner, sender_addr, sender_vk)?,
                type_,
                intent_hash: crate::balance_tx::parse_intent_hash_hex(&u.intent_hash)?,
                output_no: u32::try_from(u.output_index)
                    .map_err(|_| err("output index out of range"))?,
            });
        }
        let owed = total.saturating_sub(d.value);
        if owed > 0 {
            change.push(UtxoOutput {
                value: owed,
                owner: maker,
                type_,
            });
        }
    }
    Ok((inputs, change, spent))
}

/// Build a Zswap offer of shielded outputs to their recipients, bound to `segment`.
fn build_shielded_output_offer(
    signer: &MidnightSigner,
    segment: u16,
    outputs_requested: &[&DesiredOutput],
) -> Result<Option<ZswapOffer<ProofPreimage, InMemoryDB>>, std::io::Error> {
    if outputs_requested.is_empty() {
        return Ok(None);
    }
    let mut rng = OsRng;
    let mut outputs = Vec::with_capacity(outputs_requested.len());
    for d in outputs_requested {
        if d.value == 0 {
            return Err(err("desired output value must be greater than zero"));
        }
        let type_ = wire_type_to_shielded(&d.token_type)?;
        let (cpk, epk) = decode_shielded_recipient(signer, &d.recipient)?;
        let coin = CoinInfo {
            nonce: rng.r#gen(),
            type_,
            value: d.value,
        };
        let out = ZswapOutput::new(&mut rng, &coin, Some(segment), &cpk, Some(epk))
            .map_err(|e| err(format!("shielded output failed: {e:?}")))?;
        outputs.push(out);
    }
    ZswapOffer::new(vec![], outputs, vec![])
        .map(Some)
        .ok_or_else(|| err("shielded Zswap offer is empty"))
}

/// The movement a built transaction makes for the wallet of `crypto_provider` on `chain_id`, read off
/// the transaction alone: each unshielded coin the wallet's key spends is an outflow, each unshielded
/// output to the wallet's address and each shielded output it can decrypt an inflow. It knows nothing
/// of the request, so a test can hold the request-derived effects against what was actually built.
/// The transaction must spend no shielded coin, whose outflow only the wallet's nullifiers tell.
#[cfg(test)]
pub(super) fn built_movement(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    stx: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Vec<TransactionEffect> {
    let addresses = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .unwrap();
    let vk = crypto_provider.unshielded_verifying_key().unwrap();
    let wallet = UserAddress::from(vk.clone());
    let mut moved: Vec<(TransferKind, String, i128)> = Vec::new();
    for pair in stx.intents.iter() {
        let (_, intent) = pair.deref();
        assert!(
            intent.dust_actions.is_none(),
            "the offer carries a DUST section"
        );
        assert_eq!(
            intent.actions.iter_deref().count(),
            0,
            "the offer calls a contract"
        );
        let offers = [
            intent.guaranteed_unshielded_offer.as_ref(),
            intent.fallible_unshielded_offer.as_ref(),
        ];
        for offer in offers.into_iter().flatten() {
            for input in offer.inputs.iter_deref().filter(|i| i.owner == vk) {
                moved.push((
                    TransferKind::Unshielded,
                    hex::encode(input.type_.0 .0),
                    -(input.value as i128),
                ));
            }
            for output in offer.outputs.iter_deref().filter(|o| o.owner == wallet) {
                moved.push((
                    TransferKind::Unshielded,
                    hex::encode(output.type_.0 .0),
                    output.value as i128,
                ));
            }
        }
    }
    let fallible = stx
        .fallible_coins
        .iter()
        .map(|pair| pair.deref().1.deref().clone());
    for offer in stx
        .guaranteed_coins
        .iter()
        .map(|sp| sp.deref().clone())
        .chain(fallible)
    {
        assert_eq!(
            offer.inputs.iter_deref().count(),
            0,
            "the offer spends a shielded coin"
        );
        for (token, value) in crypto_provider.recognize_shielded_inflow(&offer) {
            moved.push((
                TransferKind::Shielded,
                hex::encode(token.0 .0),
                value as i128,
            ));
        }
    }
    effects_from_movements(
        &addresses,
        moved.iter().map(|(kind, token_type, value)| Movement {
            kind: *kind,
            token_type,
            value: *value,
        }),
    )
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;

    /// A sender-owned NIGHT UTXO. `owner == "sender"` matches the sender address directly (no vk hex
    /// needed), and `token_type` is the NIGHT wire (32 zero bytes).
    fn night_utxo(value: u128, ih_byte: u8, out_idx: i64) -> crate::UnshieldedUtxo {
        crate::UnshieldedUtxo {
            token_type: "00".repeat(32),
            value,
            intent_hash: hex::encode([ih_byte; 32]),
            output_index: out_idx,
            owner: "sender".to_string(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    fn night_input(value: u128) -> DesiredInput {
        DesiredInput {
            kind: TransferKind::Unshielded,
            token_type: "night".to_string(),
            value,
        }
    }

    /// Two `desiredInputs` rows for the same token must select DISTINCT coins: the `claimed` set stops
    /// the second row from re-picking the first row's coin, which would double-spend it.
    #[test]
    fn same_token_desired_inputs_claim_disjoint_coins() {
        let seed = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let vk = MidnightSigningKey::from_bytes(&hex::decode(seed).unwrap())
            .unwrap()
            .verifying_key();
        // Two equal NIGHT coins; each row needs one coin's worth.
        let pool = vec![night_utxo(100, 1, 0), night_utxo(100, 2, 1)];
        let d1 = night_input(60);
        let d2 = night_input(60);
        let (inputs, _change, _spent) =
            select_unshielded_inputs(&pool, &[&d1, &d2], "sender", &vk, vk.clone().into()).unwrap();
        assert_eq!(inputs.len(), 2, "one coin selected per row");
        assert_ne!(
            inputs[0].output_no, inputs[1].output_no,
            "the two rows must not double-select the same coin"
        );
    }

    #[test]
    fn parses_inputs_outputs_and_defaults() {
        let req = parse_make_intent_json(
            r#"{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"100"}],"desiredOutputs":[{"kind":"shielded","type":"night","value":"50","recipient":"mn_r"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_inputs.len(), 1);
        assert_eq!(req.desired_inputs[0].value, 100);
        assert_eq!(req.desired_inputs[0].kind, TransferKind::Unshielded);
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.intent_segment, DEFAULT_INTENT_SEGMENT);
        assert_eq!(req.ttl, None);
    }

    const CHAIN: &str = "midnight:preview";

    fn provider() -> MidnightCryptoProvider {
        let mut credential = b"MNK1".to_vec();
        credential.extend_from_slice(&[0x11; 96]);
        MidnightSigner::mainnet()
            .crypto_provider(&ows_signer::SecretBytes::new(credential))
            .unwrap()
    }

    /// A NIGHT coin of the [`provider`]'s wallet on [`CHAIN`], as the indexer reports it.
    fn wallet_coin(value: u128, ih_byte: u8) -> crate::UnshieldedUtxo {
        crate::UnshieldedUtxo {
            owner: provider()
                .addresses(&MidnightNetwork::from_chain_id(CHAIN))
                .unwrap()
                .unshielded,
            ..night_utxo(value, ih_byte, 0)
        }
    }

    type ProvenTx = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

    fn standard(
        tx: ProvenTx,
    ) -> StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
        match tx {
            Transaction::Standard(stx) => stx,
            Transaction::ClaimRewards(_) => panic!("not a standard transaction"),
        }
    }

    /// The maker intent's unshielded inputs and outputs, as `(intent hash byte, value)` and values.
    fn unshielded_legs(
        stx: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
        segment: u16,
    ) -> (Vec<(u8, u128)>, Vec<u128>) {
        let intent = stx.intents.get(&segment).expect("the maker intent");
        let offer = intent
            .guaranteed_unshielded_offer
            .as_ref()
            .expect("an unshielded offer");
        let inputs = offer
            .inputs
            .iter_deref()
            .map(|i| (i.intent_hash.0 .0[0], i.value))
            .collect();
        let outputs = offer.outputs.iter_deref().map(|o| o.value).collect();
        (inputs, outputs)
    }

    /// The plan fixes the expiry before the policy pass: a request's own `ttl` is kept, and an omitted
    /// one becomes the wallet default once, flagged as such, and is what gets built.
    #[test]
    fn the_plan_fixes_the_offers_expiry_for_the_policy_pass() {
        let parse = |options: &str| {
            parse_make_intent_json(&format!(
                r#"{{"desiredInputs":[{{"kind":"unshielded","type":"night","value":1}}],"options":{options}}}"#
            ))
            .unwrap()
        };
        let pool = [wallet_coin(10, 1)];
        let plan = |req| plan_from_pool(CHAIN, &provider(), req, &pool, None).unwrap();
        let requested = now_secs() + 30;
        let explicit = plan(parse(&format!(r#"{{"ttl":{requested},"intentId":7}}"#)));
        assert_eq!(
            explicit.offer_context(),
            crate::policy_context::OfferContext {
                intent_id: 7,
                ttl: requested,
                ttl_is_default: false,
            }
        );

        let now = now_secs();
        let defaulted = plan(parse("{}"));
        let offer = defaulted.offer_context();
        assert!(offer.ttl_is_default);
        assert_eq!(offer.intent_id, DEFAULT_INTENT_SEGMENT);
        assert!(offer.ttl >= now + max_ttl_secs() && offer.ttl <= now + max_ttl_secs() + 2);
        let built = defaulted.offer.mock_proven(&provider()).unwrap();
        assert_eq!(
            built.intents.get(&DEFAULT_INTENT_SEGMENT).unwrap().ttl,
            Timestamp::from_secs(offer.ttl)
        );
    }

    /// The coins a maker offer spends are picked when it is planned, before the policy pass, and
    /// `authorize` spends exactly those: it proves the planned offer and has no coin set to pick from
    /// again. The movement they make is the one the policy pass saw, since the excess of the whole coin
    /// returns to the maker.
    #[test]
    fn authorize_spends_the_coins_the_plan_picked() {
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":"250"}],"desiredOutputs":[]}"#,
        )
        .unwrap();
        let pool = [
            wallet_coin(300, 1),
            wallet_coin(200, 2),
            wallet_coin(100, 3),
        ];
        let plan = plan_from_pool(CHAIN, &provider(), req, &pool, None).unwrap();
        let effects = request_effects(CHAIN, &provider(), plan.request()).unwrap();
        assert_eq!(effects[0].diff, vec![("00".repeat(32), "-250".to_string())]);

        let planned = unshielded_legs(
            &plan.offer.mock_proven(&provider()).unwrap(),
            DEFAULT_INTENT_SEGMENT,
        );
        assert_eq!(planned, (vec![(1, 300)], vec![50]));

        let signable = authorize(CHAIN, &provider(), plan, None).unwrap();
        let mut r: &[u8] = &signable;
        let authorized: ProvenTx = midnight_serialize::tagged_deserialize(&mut r).unwrap();
        assert_eq!(
            unshielded_legs(&standard(authorized), DEFAULT_INTENT_SEGMENT),
            planned
        );
    }

    /// A maker offer moves exactly what its request declares. The coins the plan picks are whole and
    /// their excess returns to the maker, outputs to anyone else are not the maker's movement, and
    /// shielded receipts to the maker count as they would on chain, so the movement read off the offer
    /// actually built equals the request-derived effects the policy pass gates on.
    #[test]
    fn request_effects_are_the_movement_of_the_offer_built() {
        let token = |b: u8| hex::encode([b; 32]);
        let own = provider()
            .addresses(&MidnightNetwork::from_chain_id(CHAIN))
            .unwrap();
        let mut other_key = b"MNK1".to_vec();
        other_key.extend_from_slice(&[0x22; 96]);
        let other = MidnightSigner::preview()
            .derive_addresses(&other_key)
            .unwrap();
        let req = parse_make_intent_json(&format!(
            r#"{{"desiredInputs":[
                {{"kind":"unshielded","type":"night","value":"250"}},
                {{"kind":"unshielded","type":"{t}","value":"40"}}],
              "desiredOutputs":[
                {{"kind":"unshielded","type":"night","value":"30","recipient":"{own_u}"}},
                {{"kind":"unshielded","type":"{u}","value":"70","recipient":"{own_u}"}},
                {{"kind":"unshielded","type":"night","value":"500","recipient":"{other_u}"}},
                {{"kind":"shielded","type":"{s}","value":"10","recipient":"{own_s}"}},
                {{"kind":"shielded","type":"{s}","value":"15","recipient":"{other_s}"}}]}}"#,
            t = token(0x5a),
            u = token(0x5b),
            s = token(0x5c),
            own_u = own.unshielded,
            own_s = own.shielded,
            other_u = other.unshielded,
            other_s = other.shielded,
        ))
        .unwrap();
        let pool = [
            wallet_coin(300, 1),
            wallet_coin(200, 2),
            crate::UnshieldedUtxo {
                token_type: token(0x5a),
                ..wallet_coin(50, 3)
            },
        ];

        let plan = plan_from_pool(CHAIN, &provider(), req, &pool, None).unwrap();
        let built = plan.offer.mock_proven(&provider()).unwrap();
        let declared = request_effects(CHAIN, &provider(), plan.request()).unwrap();

        assert_eq!(built_movement(CHAIN, &provider(), &built), declared);
        let mut picked = unshielded_legs(&built, DEFAULT_INTENT_SEGMENT).0;
        picked.sort();
        assert_eq!(
            picked,
            vec![(1, 300), (3, 50)],
            "whole coins, largest first"
        );
    }

    /// A shielded input is funded the same way: the whole coins the plan picks, less the change it
    /// mints back to the maker, are exactly the declared input.
    #[test]
    fn shielded_input_coins_net_to_the_declared_input() {
        use midnight_base_crypto::hash::HashOutput;
        use rand::Rng as _;
        let token = ShieldedTokenType(HashOutput([0x5c; 32]));
        let coin = |type_, value| {
            let mut coin: QualifiedInfo = OsRng.r#gen();
            coin.type_ = type_;
            coin.value = value;
            coin
        };
        let coins = [
            coin(token, 20),
            coin(token, 15),
            coin(token, 30),
            coin(ShieldedTokenType(HashOutput([0x5d; 32])), 99),
        ];
        let input = DesiredInput {
            kind: TransferKind::Shielded,
            token_type: hex::encode([0x5c; 32]),
            value: 25,
        };
        let req = MakeIntentRequest {
            desired_inputs: vec![input.clone()],
            desired_outputs: vec![],
            intent_segment: DEFAULT_INTENT_SEGMENT,
            ttl: None,
        };

        let selection = crate::balance_tx::plan_shielded_inputs(
            &coins,
            &shielded_input_deficits(&[&input]).unwrap(),
        )
        .unwrap();
        let spent: u128 = selection.coins.iter().map(|c| c.value).sum();
        let change: u128 = selection.change_by_token.iter().map(|(_, v)| *v).sum();
        assert!(selection.coins.iter().all(|c| c.type_ == token));

        let declared = request_effects(CHAIN, &provider(), &req).unwrap();
        assert_eq!(declared.len(), 1);
        assert_eq!(
            declared[0].diff,
            vec![(
                hex::encode([0x5c; 32]),
                (change as i128 - spent as i128).to_string()
            )]
        );
    }

    #[test]
    fn honours_requested_ttl() {
        let ttl = now_secs() + 30;
        let req = parse_make_intent_json(&format!(
            r#"{{"desiredInputs":[{{"kind":"unshielded","type":"night","value":1}}],"options":{{"ttl":{ttl}}}}}"#
        ))
        .unwrap();
        assert_eq!(req.ttl, Some(Timestamp::from_secs(ttl)));
    }

    /// A misspelled option is refused, not dropped: a `TTL` that quietly fell back to the default would
    /// leave a sealed offer open longer than the maker asked.
    #[test]
    fn a_misspelled_option_is_refused() {
        for bad in [r#"{"TTL":1}"#, r#"{"intentID":2}"#, r#"{"payfees":false}"#] {
            let json = format!(
                r#"{{"desiredInputs":[{{"kind":"unshielded","type":"night","value":1}}],"options":{bad}}}"#
            );
            let err = parse_make_intent_json(&json).unwrap_err().to_string();
            assert!(err.contains("unknown field"), "{bad}: {err}");
        }
    }

    /// An unfilled `type` would otherwise parse as NIGHT.
    #[test]
    fn a_blank_token_type_is_refused() {
        for t in ["", "  "] {
            let json =
                format!(r#"{{"desiredInputs":[{{"kind":"unshielded","type":"{t}","value":1}}]}}"#);
            assert!(parse_make_intent_json(&json).is_err(), "{t:?}");
        }
    }

    #[test]
    fn rejects_ttl_at_or_before_now() {
        // The ledger rejects an intent whose ttl is behind the block it lands in, and that block is never
        // earlier than now — so an already-past ttl can only ever produce a dead offer.
        let now = 1_000_000;
        assert!(parse_intent_ttl(Some(now), now).is_err());
        assert!(parse_intent_ttl(Some(now - 1), now).is_err());
        assert!(parse_intent_ttl(Some(now + 1), now).is_ok());
    }

    #[test]
    fn rejects_ttl_beyond_the_ledger_window() {
        // `ttl > tblock + global_ttl` is IntentTtlTooFarInFuture; measured from now, the furthest expiry
        // guaranteed to be accepted whenever the offer settles is now + global_ttl.
        let now = 1_000_000;
        let max = now + max_ttl_secs();
        assert!(parse_intent_ttl(Some(max), now).is_ok());
        assert!(parse_intent_ttl(Some(max + 1), now).is_err());
    }

    #[test]
    fn omitted_ttl_leaves_the_wallet_default() {
        // A spec-shaped request that names no ttl must behave exactly as before the option existed.
        assert_eq!(parse_intent_ttl(None, now_secs()).unwrap(), None);
        let default = default_intent_ttl().to_secs();
        let now = now_secs();
        assert!(default >= now + max_ttl_secs() && default <= now + max_ttl_secs() + 2);
    }

    #[test]
    fn honours_intent_id_and_fee_free_pay_fees() {
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"options":{"intentId":3,"payFees":false}}"#,
        )
        .unwrap();
        assert_eq!(req.intent_segment, 3);
    }

    #[test]
    fn draws_a_fallible_segment_for_random_intent_id() {
        for _ in 0..32 {
            let req = parse_make_intent_json(
                r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"options":{"intentId":"random"}}"#,
            )
            .unwrap();
            assert!(req.intent_segment >= 1);
        }
    }

    #[test]
    fn rejects_intent_id_zero_and_out_of_range() {
        // Segment 0 is the transaction's guaranteed section; the ledger rejects an intent declared
        // there, so the parse must reject it up front instead of building a doomed offer. Above the
        // 16-bit segment space there is no segment to key at at all.
        assert!(resolve_intent_segment(Some(IntentIdJson::Segment(0))).is_err());
        assert!(resolve_intent_segment(Some(IntentIdJson::Segment(u16::MAX as u64 + 1))).is_err());
        assert_eq!(
            resolve_intent_segment(Some(IntentIdJson::Segment(u16::MAX as u64))).unwrap(),
            u16::MAX
        );
        assert_eq!(
            resolve_intent_segment(None).unwrap(),
            DEFAULT_INTENT_SEGMENT
        );
    }

    #[test]
    fn rejects_an_unknown_intent_id_keyword() {
        assert!(resolve_intent_segment(Some(IntentIdJson::Keyword("any".into()))).is_err());
    }

    #[test]
    fn rejects_pay_fees_true() {
        // This wallet's maker offer is fee-free by construction, so the honest answer to a request that
        // asks it to pay is an error, not an offer that quietly does something else.
        assert!(parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"unshielded","type":"night","value":1}],"options":{"intentId":1,"payFees":true}}"#
        )
        .is_err());
        assert!(check_pay_fees(Some(false)).is_ok());
        assert!(check_pay_fees(None).is_ok());
    }

    #[test]
    fn rejects_empty_request() {
        assert!(parse_make_intent_json(r#"{"desiredInputs":[],"desiredOutputs":[]}"#).is_err());
    }

    #[test]
    fn parses_shielded_inputs() {
        let req = parse_make_intent_json(
            r#"{"desiredInputs":[{"kind":"shielded","type":"night","value":"100"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_inputs.len(), 1);
        assert_eq!(req.desired_inputs[0].kind, TransferKind::Shielded);
    }

    fn shielded_input(value: u128) -> DesiredInput {
        DesiredInput {
            kind: TransferKind::Shielded,
            token_type: "night".into(),
            value,
        }
    }

    #[test]
    fn aggregates_repeated_shielded_inputs_of_one_token() {
        let a = shielded_input(100);
        let b = shielded_input(50);
        let deficits = shielded_input_deficits(&[&a, &b]).expect("aggregate");
        assert_eq!(deficits.len(), 1, "the same token collapses to one deficit");
        assert_eq!(
            deficits[0].1, 150,
            "declared amounts sum, so coins are selected once"
        );
    }

    #[test]
    fn shielded_input_deficits_rejects_zero_value() {
        let z = shielded_input(0);
        assert!(shielded_input_deficits(&[&z]).is_err());
    }
}
