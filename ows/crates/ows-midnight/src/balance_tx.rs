//! Wallet-side balancing of an already-proven (`proof,embedded-fr`) unsealed Midnight Standard
//! transaction against the indexer's UTXO set.
//!
//! The wallet injects its own inputs, preserving the existing ZK proofs: **shielded** coins to fund
//! every negative shielded cell in the ledger `balance()` (e.g. a contract deposit, or an offer that
//! already spends some coins but is still short), then **unshielded** inputs (and per-token change)
//! for every negative unshielded cell — NIGHT and custom tokens alike. A positive cell (spare
//! value, or what a contract mint or withdrawal leaves) is claimed instead, as an output to the
//! wallet itself in that segment. Each added shielded fragment is proved on its own and merged into
//! the matching Zswap offer. When asked to pay fees on a chain that needs DUST, the fee is
//! covered with either a signature-based **generationless** DUST fee registration funded by its own
//! unregistered NIGHT (no proving), or, when the wallet has no unregistered NIGHT capacity (its NIGHT
//! is all registered for dust generation), a proof-bearing **DUST spend** of its generated dust.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::ops::Deref as _;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::{
    Nullifier, QualifiedInfo, ShieldedTokenType, TokenType as LedgerTokenType, UnshieldedTokenType,
    UserAddress, NIGHT,
};
use midnight_ledger::dust::{
    DustActions, DustLocalState, DustPublicKey, DustRegistration, DustSpend,
    INITIAL_DUST_PARAMETERS,
};
use midnight_ledger::structure::{
    Intent, LedgerParameters, ProofKind, ProofMarker, StandardTransaction, Transaction,
    UnshieldedOffer, UtxoOutput, UtxoSpend,
};
use midnight_serialize::{
    tagged_deserialize, tagged_serialize, Deserializable as _, Serializable as _,
};
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::local::State as ZswapLocalState;
use midnight_zswap::Offer as ZswapOffer;
use ows_signer::chains::midnight::MidnightAddresses;
use ows_signer::chains::{
    DustSpendPlan, MidnightCryptoProvider, MidnightNetwork, ShieldedAuthorized, ShieldedSpendPlan,
};
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof as ZswapProof;

use ows_core::policy::TransactionEffect;
use ows_core::sync_cache::SyncCacheScope;

use crate::contracts::{contract_interactions, ContractInteraction};
use crate::UnshieldedUtxo;

mod fee_sizing;
pub(crate) use fee_sizing::{size_merge_dust_fee, splice_mock_shielded_for_sizing};
use fee_sizing::{DustFeeContext, DustFeePlan};

type TxProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

pub(crate) fn parse_intent_hash_hex(
    s: &str,
) -> Result<midnight_ledger::structure::IntentHash, std::io::Error> {
    use midnight_base_crypto::hash::HashOutput;
    use midnight_ledger::structure::IntentHash;
    let hex_s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_s).map_err(|e| err(format!("invalid intent hash: {e}")))?;
    if bytes.len() != 32 {
        return Err(err("intent hash must be 32 bytes"));
    }
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Ok(IntentHash(HashOutput(h)))
}

/// Resolve a UTXO owner field (32-byte hex x-only pubkey, or the sender's own address) to a
/// verifying key.
pub(crate) fn resolve_owner_vk(
    owner_field: &str,
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
) -> Result<VerifyingKey, std::io::Error> {
    let hex_s = owner_field.strip_prefix("0x").unwrap_or(owner_field);
    if let Ok(bytes) = hex::decode(hex_s) {
        if bytes.len() == 32 {
            let mut cur = Cursor::new(bytes);
            return VerifyingKey::deserialize(&mut cur, 0)
                .map_err(|e| err(format!("invalid owner verifying key: {e}")));
        }
    }
    if owner_field == sender_bech32 {
        return Ok(sender_vk.clone());
    }
    Err(err(
        "UTXO owner must be 32-byte hex x-only pubkey or the sender's unshielded address",
    ))
}

fn owner_matches_sender(owner: &str, sender_bech32: &str, vk_hex: &str) -> bool {
    if owner == sender_bech32 {
        return true;
    }
    let o = owner.strip_prefix("0x").unwrap_or(owner);
    o.eq_ignore_ascii_case(vk_hex)
}

/// Return sender-owned UTXOs for `token_wire`, sorted (largest first) for coin selection.
fn sender_utxos_sorted(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
    token_wire: &str,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let mut vk_raw = Vec::new();
    sender_vk
        .serialize(&mut vk_raw)
        .map_err(|e| err(e.to_string()))?;
    let vk_hex = hex::encode(&vk_raw);

    let mut cand: Vec<_> = utxos
        .iter()
        .filter(|u| owner_matches_sender(&u.owner, sender_bech32, &vk_hex))
        .filter(|u| u.token_type.eq_ignore_ascii_case(token_wire))
        .cloned()
        .collect();
    cand.sort_by(|a, b| b.value.cmp(&a.value));
    Ok(cand)
}

/// Pick just enough sender-owned UTXOs for `token_wire` to cover `need`.
pub(crate) fn select_utxos_for_token(
    utxos: &[UnshieldedUtxo],
    sender_bech32: &str,
    sender_vk: &VerifyingKey,
    token_wire: &str,
    need: u128,
) -> Result<Vec<UnshieldedUtxo>, std::io::Error> {
    let cand = sender_utxos_sorted(utxos, sender_bech32, sender_vk, token_wire)?;
    let mut out = Vec::new();
    let mut sum = 0u128;
    for u in cand {
        if sum >= need {
            break;
        }
        sum = sum.saturating_add(u.value);
        out.push(u);
    }
    if sum < need {
        return Err(err(format!(
            "insufficient balance for token {token_wire}: need {need}, have {sum}"
        )));
    }
    Ok(out)
}

/// Wire hex for an unshielded token type (32 zero bytes for NIGHT).
fn unshielded_token_wire(tt: UnshieldedTokenType) -> String {
    hex::encode(tt.0 .0)
}

fn add_u128<K: Ord>(map: &mut BTreeMap<K, u128>, key: K, amount: u128) {
    let e = map.entry(key).or_default();
    *e = e.saturating_add(amount);
}

/// One side of a ledger `balance()` walk, split by domain: the negative cells (what the wallet must
/// supply) or the positive ones (value no output receives yet), each as `(token, amount, segment)`.
struct LedgerCells {
    shielded: Vec<(ShieldedTokenType, u128, u16)>,
    unshielded: Vec<(UnshieldedTokenType, u128, u16)>,
}

fn ledger_token_cells(tx: &TxProven, surplus: bool) -> Result<LedgerCells, std::io::Error> {
    let mut shielded = Vec::new();
    let mut unshielded = Vec::new();
    for ((token, segment), bal) in tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
    {
        if bal == 0 || (bal > 0) != surplus {
            continue;
        }
        let amount = bal.unsigned_abs();
        match token {
            LedgerTokenType::Shielded(tt) => shielded.push((tt, amount, segment)),
            LedgerTokenType::Unshielded(tt) => unshielded.push((tt, amount, segment)),
            LedgerTokenType::Dust => {}
        }
    }
    Ok(LedgerCells {
        shielded,
        unshielded,
    })
}

fn ledger_token_deficits(tx: &TxProven) -> Result<LedgerCells, std::io::Error> {
    ledger_token_cells(tx, false)
}

/// The wallet's claim on a transaction's surplus: an output to itself for every positive balance.
/// The ledger rejects only a negative balance, so value no output receives would otherwise be destroyed
/// when the transaction is applied, or, for NIGHT, fail the ledger's supply check. Unshielded claims
/// ride the guaranteed balancing offer (segment 0 nets every intent's guaranteed offer) or that
/// segment's fallible offer; shielded claims become self-outputs in that segment's shielded plan.
#[derive(Debug, Default, PartialEq, Eq)]
struct SurplusClaims {
    guaranteed: Vec<UtxoOutput>,
    fallible: BTreeMap<u16, Vec<UtxoOutput>>,
    shielded: BTreeMap<u16, Vec<(ShieldedTokenType, u128)>>,
}

fn surplus_claims(tx: &TxProven, wallet: UserAddress) -> Result<SurplusClaims, std::io::Error> {
    let cells = ledger_token_cells(tx, true)?;
    let mut claims = SurplusClaims::default();
    for (token, value, segment) in cells.unshielded {
        let output = UtxoOutput {
            value,
            owner: wallet,
            type_: token,
        };
        if segment == 0 {
            claims.guaranteed.push(output);
        } else {
            claims.fallible.entry(segment).or_default().push(output);
        }
    }
    for (token, value, segment) in cells.shielded {
        claims
            .shielded
            .entry(segment)
            .or_default()
            .push((token, value));
    }
    Ok(claims)
}

/// Per-segment shielded token deficits (ledger `balance` negative = overspend).
fn ledger_shielded_deficits(
    tx: &TxProven,
) -> Result<Vec<(ShieldedTokenType, u128, u16)>, std::io::Error> {
    Ok(ledger_token_deficits(tx)?.shielded)
}

/// Per-segment unshielded token deficits (ledger `balance` negative = overspend). Covers NIGHT and
/// custom unshielded tokens.
fn ledger_unshielded_deficits(
    tx: &TxProven,
) -> Result<Vec<(UnshieldedTokenType, u128, u16)>, std::io::Error> {
    Ok(ledger_token_deficits(tx)?.unshielded)
}

/// Nullifiers already spent by the transaction's Zswap offers — excluded from the wallet's funding
/// selection so a top-up never double-spends a coin the dapp (or a prior merge) already spent.
fn spent_shielded_nullifiers(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> BTreeSet<Nullifier> {
    let mut spent = BTreeSet::new();
    if let Some(offer) = base.guaranteed_coins.as_ref() {
        for input in offer.inputs.iter_deref() {
            spent.insert(input.nullifier);
        }
    }
    for pair in base.fallible_coins.iter() {
        let (_seg, offer_sp) = pair.deref();
        for input in offer_sp.inputs.iter_deref() {
            spent.insert(input.nullifier);
        }
    }
    spent
}

/// Return ledger per-segment imbalances (negative = overspend).
fn tx_balance_imbalances(tx: &TxProven) -> Result<Vec<String>, std::io::Error> {
    let imbalances: Vec<String> = tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?
        .into_iter()
        .filter(|(_, bal)| *bal < 0)
        .map(|((_, segment), bal)| format!("segment {segment} overspent by {}", bal.unsigned_abs()))
        .collect();
    Ok(imbalances)
}

/// Route a proven shielded fragment into the offer the signer bound it to: `segment == 0` merges into
/// the guaranteed offer; `segment >= 1` merges into `fallible_coins[segment]` (creating that segment's
/// entry if absent). Placement must match the segment the fragment's spends/proofs were bound to —
/// `well_formed` verifies the guaranteed offer at a hardcoded segment 0 and each fallible offer at its
/// map-key segment, and `balance()` attributes deltas the same way — so a seg-N>=1 fragment in the
/// guaranteed offer would fail proof verification and leave the seg-N deficit uncovered.
pub(crate) fn place_shielded_fragment(
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    segment: u16,
    proven: &ZswapOffer<ZswapProof, InMemoryDB>,
) -> Result<(), std::io::Error> {
    if segment == 0 {
        let merged = match base.guaranteed_coins.as_ref() {
            Some(sp) => sp
                .deref()
                .merge(proven)
                .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?,
            None => proven.clone(),
        };
        base.guaranteed_coins = Some(Sp::new(merged));
    } else {
        let merged = match base.fallible_coins.get(&segment) {
            Some(sp) => sp
                .deref()
                .merge(proven)
                .map_err(|e| err(format!("merge shielded zswap offers: {e}")))?,
            None => proven.clone(),
        };
        base.fallible_coins = base.fallible_coins.insert(segment, merged);
    }
    Ok(())
}

/// Reassemble a proven `StandardTransaction`, replacing only the balanced intent (`seg_id`) and
/// preserving every other intent, the shielded Zswap offers, binding randomness (must already match
/// `guaranteed_coins` / intents), and the input transaction's network id.
fn wrap_proven_standard(
    stx_in: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_out: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> TxProven {
    // Replace only the intent the wallet balanced; the dapp's other intents carry through untouched.
    let intents = stx_in.intents.insert(seg_id, intent_out);
    Transaction::Standard(StandardTransaction {
        network_id: stx_in.network_id.clone(),
        intents,
        guaranteed_coins: stx_in.guaranteed_coins.clone(),
        fallible_coins: stx_in.fallible_coins.clone(),
        binding_randomness: stx_in.binding_randomness,
    })
}

/// The on-chain identity of an unshielded UTXO (producing intent hash + output index), used to keep the
/// guaranteed offer and each per-segment fallible offer drawing **disjoint** coins from one pool.
type UtxoKey = (String, i64);

/// Claim `u` into `claimed` and turn it into an unsigned spend of `token`.
fn claim_utxo_spend(
    u: &UnshieldedUtxo,
    token: UnshieldedTokenType,
    claimed: &mut Vec<UtxoKey>,
    sender_addr: &str,
    sender_vk: &VerifyingKey,
) -> Result<UtxoSpend, std::io::Error> {
    claimed.push((u.intent_hash.clone(), u.output_index));
    let ih = parse_intent_hash_hex(&u.intent_hash)?;
    let out_no = u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
    let vk = resolve_owner_vk(&u.owner, sender_addr, sender_vk)?;
    Ok(UtxoSpend {
        value: u.value,
        owner: vk,
        type_: token,
        intent_hash: ih,
        output_no: out_no,
    })
}

/// Build one balancing unshielded offer from a pre-fetched UTXO `pool`: for each per-token `deficit`,
/// select just enough sender coins of that type — skipping coins already `claimed` by another offer,
/// so no coin is spent twice — then emit those inputs plus `outputs_in` (the offer's own outputs,
/// re-emitted) and a change output per token. An optional NIGHT `reserve` is spent balance-neutrally
/// so its unregistered capacity can back a generationless DUST fee registration. Records every coin
/// it claims into `claimed` and returns the selected UTXOs (fee sizing filters to NIGHT). Sorted for
/// ledger validity; signatures are appended later by the signer, so the offer starts unsigned.
fn build_unshielded_balancing_offer(
    pool: &[UnshieldedUtxo],
    claimed: &mut Vec<UtxoKey>,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    deficits: &[(UnshieldedTokenType, u128)],
    outputs_in: Vec<UtxoOutput>,
    reserve: Option<&UnshieldedUtxo>,
) -> Result<(UnshieldedOffer<MnSig, InMemoryDB>, Vec<UnshieldedUtxo>), std::io::Error> {
    let sender_user = UserAddress::from(sender_vk.clone());
    let mut need_by_token: BTreeMap<UnshieldedTokenType, u128> = BTreeMap::new();
    for (token, need) in deficits {
        if *need > 0 {
            add_u128(&mut need_by_token, *token, *need);
        }
    }

    let mut selected_all: Vec<UnshieldedUtxo> = Vec::new();
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    let mut total_in_by_token: BTreeMap<UnshieldedTokenType, u128> = BTreeMap::new();

    // Unclaimed coins once for the whole offer; each token selection claims into `claimed` so the
    // next token (and the reserve) cannot reuse them.
    let mut available: Vec<UnshieldedUtxo> = pool
        .iter()
        .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
        .cloned()
        .collect();

    for (token, need) in &need_by_token {
        let wire = unshielded_token_wire(*token);
        let selected = select_utxos_for_token(&available, sender_addr, sender_vk, &wire, *need)?;
        for u in &selected {
            inputs.push(claim_utxo_spend(
                u,
                *token,
                claimed,
                sender_addr,
                sender_vk,
            )?);
            add_u128(&mut total_in_by_token, *token, u.value);
            selected_all.push(u.clone());
            available
                .retain(|a| !(a.intent_hash == u.intent_hash && a.output_index == u.output_index));
        }
    }

    // Reserve the best-Dust NIGHT coin for the generationless fee registration: spend it here so its
    // unregistered-NIGHT capacity backs the registration. Balance-neutral — its value returns as
    // change — and skipped when the payment already selected it or another offer claimed it, so the
    // wallet reserves exactly one coin instead of over-rotating its NIGHT.
    if let Some(r) = reserve {
        if !claimed.contains(&(r.intent_hash.clone(), r.output_index)) {
            inputs.push(claim_utxo_spend(r, NIGHT, claimed, sender_addr, sender_vk)?);
            add_u128(&mut total_in_by_token, NIGHT, r.value);
            selected_all.push(r.clone());
        }
    }

    let mut outputs = outputs_in;
    // Change per token: selected total minus the deficit funded for that token (reserve adds to
    // NIGHT total_in without raising the need, so it returns as change).
    for (token, total_in) in &total_in_by_token {
        let need = need_by_token.get(token).copied().unwrap_or(0);
        let change = total_in.saturating_sub(need);
        if change > 0 {
            outputs.push(UtxoOutput {
                value: change,
                owner: sender_user,
                type_: *token,
            });
        }
    }

    // Ledger validity requires inputs/outputs to be sorted (MalformedError::InputsNotSorted).
    inputs.sort();
    outputs.sort();

    // Start empty: `Intent::sign` appends signatures; pre-filling breaks well-formedness.
    let offer = UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    };
    Ok((offer, selected_all))
}

/// Test helper: one balancing unshielded offer that funds a single NIGHT deficit.
#[cfg(test)]
fn build_night_offer(
    pool: &[UnshieldedUtxo],
    claimed: &mut Vec<UtxoKey>,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    need_night: u128,
    outputs_in: Vec<UtxoOutput>,
    reserve: Option<&UnshieldedUtxo>,
) -> Result<(UnshieldedOffer<MnSig, InMemoryDB>, Vec<UnshieldedUtxo>), std::io::Error> {
    let deficits: Vec<(UnshieldedTokenType, u128)> = if need_night > 0 {
        vec![(NIGHT, need_night)]
    } else {
        vec![]
    };
    build_unshielded_balancing_offer(
        pool,
        claimed,
        sender_vk,
        sender_addr,
        &deficits,
        outputs_in,
        reserve,
    )
}

/// Build a fallible unshielded offer that consolidates several of the wallet's own NIGHT coins into a
/// single change output back to itself. A wallet-built fallible NIGHT offer, spent on its own segment
/// so the guaranteed section stays free for the DUST-registration cell — the mechanism behind moving
/// the wallet's NIGHT off the (budget-tight) guaranteed section. Balance-neutral: the inputs equal the
/// one change output, so the segment it is attached to nets to zero. Each spent coin is recorded in
/// `claimed` so no other offer double-spends it.
fn build_fallible_consolidation_offer(
    coins: &[UnshieldedUtxo],
    claimed: &mut Vec<UtxoKey>,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
) -> Result<UnshieldedOffer<MnSig, InMemoryDB>, std::io::Error> {
    if coins.is_empty() {
        return Err(err("fallible consolidation requires at least one coin"));
    }
    let mut total_in = 0u128;
    let mut inputs: Vec<UtxoSpend> = Vec::new();
    for u in coins {
        claimed.push((u.intent_hash.clone(), u.output_index));
        total_in = total_in.saturating_add(u.value);
        let ih = parse_intent_hash_hex(&u.intent_hash)?;
        let out_no = u32::try_from(u.output_index).map_err(|_| err("output index out of range"))?;
        let vk = resolve_owner_vk(&u.owner, sender_addr, sender_vk)?;
        inputs.push(UtxoSpend {
            value: u.value,
            owner: vk,
            type_: NIGHT,
            intent_hash: ih,
            output_no: out_no,
        });
    }
    let sender_user = UserAddress::from(inputs[0].owner.clone());
    let mut outputs = vec![UtxoOutput {
        value: total_in,
        owner: sender_user,
        type_: NIGHT,
    }];
    inputs.sort();
    outputs.sort();
    Ok(UnshieldedOffer {
        inputs: inputs.into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    })
}

/// Give the signed intent a TTL an hour past the chain tip, matching the wallet SDK.
fn chain_aligned_intent_ttl(dust_ctime: Timestamp) -> Timestamp {
    Timestamp::from_secs(dust_ctime.to_secs().saturating_add(3600))
}

/// Assemble the proven intent from the balanced offer plus optional dust actions.
fn assemble_proven_intent(
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
    fallible_offer: Option<&UnshieldedOffer<MnSig, InMemoryDB>>,
    intent_in: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    dust_actions: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ttl: Timestamp,
) -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
    Intent {
        // An empty balancing offer (no inputs, no outputs) carries nothing in the guaranteed section —
        // e.g. a fee-less transfer whose NIGHT movement rides the fallible offer, so the wallet folds no
        // guaranteed inputs here. Drop it to None rather than hand the ledger a degenerate 0-in/0-out
        // offer; a non-empty offer (own re-emitted outputs, funding inputs, or the reserved dust coin)
        // stays as-is.
        guaranteed_unshielded_offer: (offer.inputs.iter_deref().next().is_some()
            || offer.outputs.iter_deref().next().is_some())
        .then(|| Sp::new(offer.clone())),
        // Prefer the wallet's balancing fallible offer (which already re-emits the intent's own fallible
        // outputs); otherwise carry through whatever the intent held.
        fallible_unshielded_offer: fallible_offer
            .map(|o| Sp::new(o.clone()))
            .or_else(|| intent_in.fallible_unshielded_offer.clone()),
        actions: intent_in.actions.clone(),
        // Prefer the wallet's own dust section; otherwise carry through whatever the intent already
        // held — merging into a dapp intent must never silently drop its dust.
        dust_actions: dust_actions
            .or_else(|| intent_in.dust_actions.as_ref().map(|sp| sp.deref().clone()))
            .map(Sp::new),
        ttl,
        binding_commitment: intent_in.binding_commitment,
    }
}

/// Replace the fallible unshielded offer of the intent at `seg`, preserving everything else. Unshielded
/// offers are signed (not Pedersen-committed), so this leaves the tx's `binding_randomness` untouched.
/// A no-op when no intent sits at `seg`.
fn attach_fallible_offer(
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg: u16,
    offer: &UnshieldedOffer<MnSig, InMemoryDB>,
) {
    if let Some(intent_sp) = base.intents.get(&seg) {
        let mut intent = intent_sp.deref().clone();
        intent.fallible_unshielded_offer = Some(Sp::new(offer.clone()));
        base.intents = base.intents.insert(seg, intent);
    }
}

/// An empty proven intent at zero binding randomness: no offers, actions, or dust. It carries the
/// wallet's balancing offer + a dust section that needs its own timestamp onto a **fresh** segment
/// (spec §L961-967) without disturbing the dapp's proven transaction. Zero `binding_commitment` keeps
/// the added intent binding-neutral — `recompute_binding_randomness` sums each intent's
/// `binding_commitment`, so the tx's global `binding_randomness` is unchanged.
fn empty_intent_skeleton() -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
    Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: None,
        actions: vec![].into(),
        dust_actions: None,
        ttl: Timestamp::from_secs(0),
        binding_commitment: PedersenRandomness::from(0),
    }
}

/// A dust registration the dapp put in the transaction, accepted for the wallet to sign only when it
/// registers the wallet's own NIGHT to the wallet's own dust address. A registration routes that
/// NIGHT's DUST generation to `dust_address`, so any other target would give the generation away and
/// `None` (a deregistration) would switch it off. The signer enforces the same rule; checking here
/// fails the request before anything is proven.
fn check_carried_registration(
    reg: &DustRegistration<MnSig, InMemoryDB>,
    wallet_vk: &VerifyingKey,
    wallet_dust_address: &DustPublicKey,
) -> Result<(), std::io::Error> {
    if reg.night_key != *wallet_vk {
        return Err(err(
            "transaction carries a dust registration for another NIGHT key, which the wallet \
             cannot sign",
        ));
    }
    match reg.dust_address.as_deref() {
        Some(addr) if addr == wallet_dust_address => Ok(()),
        Some(_) => Err(err(
            "transaction carries a dust registration to another dust address; the wallet only \
             signs one to its own",
        )),
        None => Err(err(
            "transaction carries a dust deregistration, which the wallet refuses to sign",
        )),
    }
}

/// The next unused intent segment id: one past the current maximum. Intents never sit at segment 0
/// (reserved for the guaranteed section), so this is always `>= 1`. Errors when an intent already
/// sits at the last segment (`u16::MAX`), which the ledger allows.
fn fresh_segment_id(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Result<u16, std::io::Error> {
    let max = base
        .intents
        .iter()
        .map(|pair| *pair.deref().0.deref())
        .max();
    match max {
        Some(max) => max.checked_add(1).ok_or_else(|| {
            err(format!(
                "transaction has no free intent segment for the wallet's intent: an intent already \
                 sits at segment {max}"
            ))
        }),
        None => Ok(1),
    }
}

/// Add a new intent at `seg`, refusing a segment the transaction already uses: inserting there would
/// silently replace the dapp's intent.
fn insert_new_intent(
    base: &mut StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg: u16,
    intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Result<(), std::io::Error> {
    if base.intents.contains_key(&seg) {
        return Err(err(format!("intent segment {seg} is already taken")));
    }
    base.intents = base.intents.insert(seg, intent);
    Ok(())
}

/// Clone an unshielded offer's outputs for re-emit when the wallet replaces that offer with a funded one.
fn offer_outputs(offer: &UnshieldedOffer<MnSig, InMemoryDB>) -> Vec<UtxoOutput> {
    offer
        .outputs
        .iter_deref()
        .map(|o| UtxoOutput {
            value: o.value,
            owner: o.owner,
            type_: o.type_,
        })
        .collect()
}

/// The intent's fallible unshielded outputs, cloned — re-emitted by the balancing offer that replaces
/// that intent's fallible offer when the wallet funds its deficit.
fn fallible_outputs_of(
    intent: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Vec<UtxoOutput> {
    intent
        .fallible_unshielded_offer
        .as_ref()
        .map(|sp| offer_outputs(sp.deref()))
        .unwrap_or_default()
}

/// The intent's guaranteed unshielded outputs, cloned — re-emitted by the balancing offer that replaces
/// that intent's guaranteed offer when the wallet merges into it.
fn guaranteed_outputs_of(
    intent: &Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
) -> Vec<UtxoOutput> {
    intent
        .guaranteed_unshielded_offer
        .as_ref()
        .map(|sp| offer_outputs(sp.deref()))
        .unwrap_or_default()
}

/// Where the wallet folds its balancing inputs: the segment, the intent it rebuilds there, and that
/// intent's guaranteed outputs to re-emit.
type BalancingIntent = (
    u16,
    Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    Vec<UtxoOutput>,
);

/// Pick the intent the wallet folds its balancing offer + dust fee into, or synthesize a fresh empty
/// skeleton when there is none to reuse.
///
/// Reuse the lowest-segment existing intent (re-emitting its own guaranteed outputs) unless a fresh
/// skeleton is required — which happens in two cases:
/// - the tx carries **no reusable intent** at all: a shielded-only transaction lives entirely in
///   `guaranteed_coins`/`fallible_coins` and has an **empty** `intents` map, so the wallet's dust fee
///   has nowhere to go without a new intent; or
/// - the tx **already carries a dust section**: an intent holds only one dust section and the wallet's
///   dust needs its own timestamp, so it rides a brand-new intent (spec §L961-967).
///
/// The fresh skeleton sits at a new segment with no outputs to re-emit — every existing intent keeps its
/// own guaranteed offer, so their outputs stay put — and is binding-neutral.
fn balancing_intent(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    chosen: Option<(
        u16,
        Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    )>,
    adding_dust: bool,
    has_preexisting_dust: bool,
) -> Result<BalancingIntent, std::io::Error> {
    match chosen {
        Some((seg_id, intent_in)) if !(adding_dust && has_preexisting_dust) => {
            let outputs_in = guaranteed_outputs_of(&intent_in);
            Ok((seg_id, intent_in, outputs_in))
        }
        _ => Ok((fresh_segment_id(base)?, empty_intent_skeleton(), Vec::new())),
    }
}

/// The wallet's inert shielded funding plan for one intent segment: the coins to spend — chosen whole
/// and largest-first to cover each per-token deficit — and the self-change to mint per token. Built
/// from the synced coin set alone (viewing + nullifier detection), it carries **no** spend witness, so
/// it is not a bearer instrument; the authorizing `spend()` happens later, in the signer's
/// [`MidnightCryptoProvider::authorize_shielded`], after the policy seam.
#[derive(Debug, Clone)]
pub(crate) struct SegmentPlan {
    pub(crate) coins: Vec<QualifiedInfo>,
    pub(crate) change_by_token: Vec<(ShieldedTokenType, u128)>,
}

/// Choose which of the wallet's coins to spend to cover each per-token `deficit` — whole coins,
/// largest-first — and size the self-change (selected total − deficit) per token. Pure over the synced
/// coin set: it neither spends nor proves, so it needs no spend key (only the viewing/nullifier
/// detection that produced `coins`). Errors when a token's coins cannot cover its deficit.
pub(crate) fn plan_shielded_inputs(
    coins: &[QualifiedInfo],
    deficits: &[(ShieldedTokenType, u128)],
) -> Result<SegmentPlan, std::io::Error> {
    let mut selected = Vec::new();
    let mut change_by_token = Vec::new();

    for (token, need) in deficits {
        if *need == 0 {
            continue;
        }
        let mut candidates: Vec<QualifiedInfo> = coins
            .iter()
            .copied()
            .filter(|c| c.type_ == *token)
            .collect();
        candidates.sort_by(|a, b| b.value.cmp(&a.value));

        let mut remaining = *need;
        let mut spent = 0u128;
        for coin in candidates {
            if remaining == 0 {
                break;
            }
            selected.push(coin);
            spent = spent.saturating_add(coin.value);
            remaining = remaining.saturating_sub(coin.value);
        }
        if remaining > 0 {
            return Err(err(format!(
                "insufficient shielded balance for token {}: need {need}, short by {remaining}",
                hex::encode(token.into_inner().0)
            )));
        }
        let change = spent.saturating_sub(*need);
        if change > 0 {
            change_by_token.push((*token, change));
        }
    }

    Ok(SegmentPlan {
        coins: selected,
        change_by_token,
    })
}

/// The wallet's shielded funding plan for an unsealed proven tx: the per-segment [`ShieldedSpendPlan`]s
/// (which coins to spend + change to mint) and the synced Zswap tree they were planned against — the
/// signer re-spends against this same tree to build the real witnesses. Inert: it carries no spend
/// witness, so it is not a bearer instrument.
pub(super) struct ShieldedFundingPlan {
    pub(super) plans: Vec<ShieldedSpendPlan>,
    pub(super) tree: ZswapLocalState<InMemoryDB>,
}

/// A balanced-but-unauthorized transaction: everything needed to authorize an unsealed proven tx,
/// minus the authorizing witnesses themselves. Produced by [`plan_unsealed_proven_tx`] (which syncs,
/// selects, and fee-sizes with **no** real proving) and consumed by [`authorize_proven_tx`] after the
/// policy seam. Carries no bearer instrument — the proof-preimage `spend()` witnesses are built later,
/// in the signer.
pub struct BalancedPlan {
    base: StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    seg_id: u16,
    intent_in: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    unshielded_offer: UnshieldedOffer<MnSig, InMemoryDB>,
    /// Per-segment fallible unshielded balancing offers (each funds one intent's fallible unshielded
    /// deficit in its own segment). Empty when no intent carries a fallible unshielded shortfall.
    fallible_offers: Vec<(u16, UnshieldedOffer<MnSig, InMemoryDB>)>,
    intent_ttl: Timestamp,
    shielded: Option<ShieldedFundingPlan>,
    dust: DustFeePlan,
}

impl BalancedPlan {
    /// The wallet-relative net movement authorizing this plan will have, derived from the plan alone — no
    /// re-sync, no bearer instrument — so the policy seam can gate on it *before* [`authorize_proven_tx`]
    /// builds any spend witness, grouped by the transaction segment it occurs in:
    ///
    /// - **unshielded**, per token — per its offer's segment: the guaranteed offer nets into segment
    ///   `0`, each per-segment fallible offer into its own segment. Inputs (all the wallet's) are
    ///   outflow, its own outputs (the change, and any surplus it claims) inflow.
    /// - **shielded**, per token — per its plan's segment: the coins the plan spends are outflow, the
    ///   self-outputs it mints (change and surplus claims) inflow, and a shielded output the *dapp*
    ///   routes to the wallet — recognized by trial-decrypting the base offers' outputs with the
    ///   shielded viewing key — inflow in the segment its offer rides. So the shielded effect is the
    ///   wallet's true net movement, not just an outflow bound (recognizing a receipt needs no spend
    ///   key; only recognizing a spend does).
    /// - **dust** — the DUST the fee section burns (a generationless registration burns none), attributed
    ///   to the guaranteed segment `0`: the fee pays for the guaranteed computation and is always charged.
    ///
    /// The policy seam interprets guaranteed (`0`) versus fallible (`>= 1`); here we only attribute.
    pub(crate) fn segment_effects(
        &self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Vec<SegmentEffects>, std::io::Error> {
        let addresses = crypto_provider
            .addresses(&MidnightNetwork::from_chain_id(chain_id))
            .map_err(|e| err(e.to_string()))?;
        let wallet_ua = UserAddress::from(
            crypto_provider
                .unshielded_verifying_key()
                .map_err(|e| err(e.to_string()))?,
        );
        // The wallet funds unshielded tokens through the guaranteed offer (segment 0) and any
        // per-segment fallible offer; each keeps its own segment so the policy can tell guaranteed
        // from fallible movement.
        let mut offers = vec![(0u16, &self.unshielded_offer)];
        offers.extend(
            self.fallible_offers
                .iter()
                .map(|(seg, offer)| (*seg, offer)),
        );
        let shielded_plans = self
            .shielded
            .as_ref()
            .map(|funding| funding.plans.as_slice())
            .unwrap_or(&[]);
        // Shielded receipts the dapp routes to the wallet — the inflow the wallet's own funding plan
        // (spent coins + self-change) does not carry. Recognized here by trial-decrypting the base
        // offers' outputs (viewing tier, no network), keyed by the segment each offer rides: the
        // guaranteed zswap offer into segment 0, each fallible entry into its own segment.
        let shielded_inflow = scan_shielded_inflow(
            self.base.guaranteed_coins.as_deref(),
            &self.base.fallible_coins,
            crypto_provider,
        );
        plan_segment_effects(
            &addresses,
            &wallet_ua,
            &offers,
            shielded_plans,
            &shielded_inflow,
            self.dust.dust_outflow(),
        )
    }

    /// The contract actions the transaction being balanced carries — who it talks to, and how much each
    /// contract declares it takes in and pays out. The counterpart the wallet-relative
    /// [effects](Self::segment_effects) deliberately omit; the wallet's own balancing adds no contract
    /// action, so these are entirely the dapp's.
    pub(crate) fn contracts(&self) -> Vec<ContractInteraction> {
        contract_interactions(self.base.actions())
    }
}

/// The wallet-relative DUST effect for a fee that burns `dust_outflow` — a negative diff in the `dust`
/// domain keyed by the wallet's dust address — or `None` when the fee burns nothing. The single source
/// for the dust effect's shape, shared by the balancer's [`plan_segment_effects`] and the sealed-merge
/// effects.
pub(crate) fn dust_outflow_effect(
    dust_address: String,
    dust_outflow: u128,
) -> Option<TransactionEffect> {
    (dust_outflow != 0).then(|| TransactionEffect {
        address: dust_address,
        diff: vec![("dust".to_string(), format!("-{dust_outflow}"))],
    })
}

/// The wallet's shielded receipts across a proven transaction's Zswap offers — recognized by
/// trial-decrypting each offer's outputs with the shielded viewing key — keyed by the segment its offer
/// rides: the guaranteed offer nets into segment `0`, each fallible entry into its own segment. Generic
/// over the proof marker (the recognition reads only ciphertext + commitment, both proof-independent) so
/// it is unit-testable with a proof-preimage offer, no proving.
fn scan_shielded_inflow<P: midnight_storage::Storable<InMemoryDB>>(
    guaranteed: Option<&ZswapOffer<P, InMemoryDB>>,
    fallible: &MnHashMap<u16, ZswapOffer<P, InMemoryDB>, InMemoryDB>,
    crypto_provider: &MidnightCryptoProvider,
) -> Vec<(u16, ShieldedTokenType, u128)> {
    let mut inflow = Vec::new();
    if let Some(offer) = guaranteed {
        for (token, value) in crypto_provider.recognize_shielded_inflow(offer) {
            inflow.push((0, token, value));
        }
    }
    for pair in fallible.iter() {
        let (seg_sp, offer_sp) = pair.deref();
        let seg = *seg_sp.deref();
        for (token, value) in crypto_provider.recognize_shielded_inflow(offer_sp.deref()) {
            inflow.push((seg, token, value));
        }
    }
    inflow
}

/// The wallet-relative effects authorizing a plan will have, grouped by the transaction segment they
/// occur in. `segment == 0` is the guaranteed section (always executed); `>= 1` a fallible section
/// (executed in order, allowed to fail). Attribution only — whether a fallible movement is acceptable is
/// the policy's call. Serialized into the generic `chain_extra` policy-context slot for executable
/// policies to read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SegmentEffects {
    pub segment: u16,
    pub effects: Vec<TransactionEffect>,
}

/// Wrap a flat effect list as the movement of a single segment; an empty list yields no entry. Used by
/// the `make*`/merge connectors whose whole offer rides one intent segment.
pub(crate) fn single_segment(segment: u16, effects: Vec<TransactionEffect>) -> Vec<SegmentEffects> {
    if effects.is_empty() {
        Vec::new()
    } else {
        vec![SegmentEffects { segment, effects }]
    }
}

/// Compute the wallet-relative effects from a balanced plan's already-decided parts, grouped by segment.
/// Pure over its inputs (no key, no network), so it is the unit-tested core of
/// [`BalancedPlan::segment_effects`]:
///
/// - **unshielded**, per token — per its offer's segment: the offer's inputs (all the wallet's) are
///   outflow, its wallet-owned outputs (change and surplus claims) inflow.
/// - **shielded**, per token — per its plan's segment: spent coins outflow, minted self-outputs
///   inflow, plus the dapp-routed receipts in `shielded_inflow` (recognized upstream) as inflow in
///   their offer's segment.
/// - **dust** — the DUST the fee section burns, attributed to the guaranteed segment `0`: the fee pays
///   for the guaranteed computation (only the segment-0 offer loads the fee budget) and is always
///   charged, so a policy sees it as a guaranteed outflow even when the transfer it funds is fallible.
///
/// One [`TransactionEffect`] per (segment, domain) that nets non-zero, keyed by the wallet's address for
/// that domain; a segment with no non-zero movement is omitted. Fails when an amount or a per-token net
/// falls outside `i128` (see [`signed_amount`]).
fn plan_segment_effects(
    addresses: &MidnightAddresses,
    wallet_ua: &UserAddress,
    unshielded_offers: &[(u16, &UnshieldedOffer<MnSig, InMemoryDB>)],
    shielded_plans: &[ShieldedSpendPlan],
    shielded_inflow: &[(u16, ShieldedTokenType, u128)],
    dust_outflow: u128,
) -> Result<Vec<SegmentEffects>, std::io::Error> {
    const GUARANTEED_SEGMENT: u16 = 0;
    let mut unshielded_by_seg: BTreeMap<u16, BTreeMap<UnshieldedTokenType, i128>> = BTreeMap::new();
    for (segment, offer) in unshielded_offers {
        let by_token = unshielded_by_seg.entry(*segment).or_default();
        for i in offer.inputs.iter_deref() {
            net_add(
                by_token.entry(i.type_).or_default(),
                -signed_amount(i.value)?,
            )?;
        }
        for o in offer.outputs.iter_deref() {
            if o.owner == *wallet_ua {
                net_add(
                    by_token.entry(o.type_).or_default(),
                    signed_amount(o.value)?,
                )?;
            }
        }
    }

    let mut shielded_by_seg: BTreeMap<u16, BTreeMap<ShieldedTokenType, i128>> = BTreeMap::new();
    for plan in shielded_plans {
        let by_token = shielded_by_seg.entry(plan.segment).or_default();
        for coin in &plan.coins {
            net_add(
                by_token.entry(coin.type_).or_default(),
                -signed_amount(coin.value)?,
            )?;
        }
        for (token, change) in &plan.change {
            net_add(by_token.entry(*token).or_default(), signed_amount(*change)?)?;
        }
    }
    // Shielded receipts the dapp routes to the wallet (recognized upstream by trial-decrypting the base
    // offers' outputs) are inflow in the segment their offer rides — the value the wallet's own funding
    // plan does not carry, so netting it turns the shielded effect into the wallet's true movement.
    for (segment, token, value) in shielded_inflow {
        let net = shielded_by_seg
            .entry(*segment)
            .or_default()
            .entry(*token)
            .or_default();
        net_add(net, signed_amount(*value)?)?;
    }

    // Every segment carrying any movement, plus the guaranteed segment when the fee burns dust.
    let mut segments: BTreeSet<u16> = BTreeSet::new();
    segments.extend(unshielded_by_seg.keys().copied());
    segments.extend(shielded_by_seg.keys().copied());
    if dust_outflow != 0 {
        segments.insert(GUARANTEED_SEGMENT);
    }

    let mut out = Vec::new();
    for segment in segments {
        let mut effects = Vec::new();
        if let Some(by_token) = unshielded_by_seg.get(&segment) {
            let unshielded_diff: Vec<(String, String)> = by_token
                .iter()
                .filter(|(_, v)| **v != 0)
                .map(|(token, v)| (unshielded_token_wire(*token), v.to_string()))
                .collect();
            if !unshielded_diff.is_empty() {
                effects.push(TransactionEffect {
                    address: addresses.unshielded.clone(),
                    diff: unshielded_diff,
                });
            }
        }
        if let Some(by_token) = shielded_by_seg.get(&segment) {
            let shielded_diff: Vec<(String, String)> = by_token
                .iter()
                .filter(|(_, v)| **v != 0)
                .map(|(token, v)| (hex::encode(token.into_inner().0), v.to_string()))
                .collect();
            if !shielded_diff.is_empty() {
                effects.push(TransactionEffect {
                    address: addresses.shielded.clone(),
                    diff: shielded_diff,
                });
            }
        }
        if segment == GUARANTEED_SEGMENT {
            if let Some(effect) = dust_outflow_effect(addresses.dust.clone(), dust_outflow) {
                effects.push(effect);
            }
        }
        if !effects.is_empty() {
            out.push(SegmentEffects { segment, effects });
        }
    }
    Ok(out)
}

/// `value` as a signed amount for netting effects, or an error when it doesn't fit. The ledger's own
/// balance check rejects any amount outside `i128` as malformed, so this fails exactly where the node
/// would; `value as i128` would instead wrap it into a small or opposite movement and show the policy a
/// wrong number.
pub(crate) fn signed_amount(value: u128) -> Result<i128, std::io::Error> {
    i128::try_from(value).map_err(|_| {
        err(format!(
            "amount {value} is too large to account for in the policy effects"
        ))
    })
}

/// Add `delta` into a running per-token net, failing instead of overflowing.
pub(crate) fn net_add(net: &mut i128, delta: i128) -> Result<(), std::io::Error> {
    *net = net.checked_add(delta).ok_or_else(|| {
        err("a token's net movement is too large to account for in the policy effects")
    })?;
    Ok(())
}

/// Plan the wallet's shielded funding for a proven tx: per intent segment, the coins to spend (whole,
/// largest-first) for a shielded deficit and the self-outputs to mint, which are the change from those
/// coins plus the segment's `claims` on a shielded surplus. Coin consumption is threaded across
/// segments so no coin is planned twice, and nullifiers the transaction already spends are skipped.
/// Driven by negative shielded cells in ledger `balance()` — including an offer that already has some
/// inputs but is still short. Pure selection over the synced coin set — no spend, no proving; a
/// surplus-only plan spends nothing, so it doesn't sync. Returns `None` when there is neither a
/// shortfall nor a claim.
fn plan_shielded_funding(
    base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    crypto_provider: &MidnightCryptoProvider,
    indexer_url: &str,
    scope: &SyncCacheScope,
    mut claims: BTreeMap<u16, Vec<(ShieldedTokenType, u128)>>,
) -> Result<Option<ShieldedFundingPlan>, std::io::Error> {
    let deficits = ledger_shielded_deficits(&Transaction::Standard(base.clone()))?;
    if deficits.is_empty() {
        if claims.is_empty() {
            return Ok(None);
        }
        let plans = claims
            .into_iter()
            .map(|(segment, change)| ShieldedSpendPlan {
                segment,
                coins: Vec::new(),
                change,
            })
            .collect();
        return Ok(Some(ShieldedFundingPlan {
            plans,
            tree: ZswapLocalState::new(),
        }));
    }

    let current_block_height = crate::tip_verify::fetch_current_block_height(indexer_url);
    let wallet = crate::block_on(crate::wallet_sync::shielded::sync_wallet(
        indexer_url,
        crypto_provider,
        scope,
        current_block_height,
    ))?;
    let mut tree = wallet.zswap;
    crate::wallet_sync::shielded::ensure_shielded_merkle_ready(&mut tree)?;

    let mut by_segment: BTreeMap<u16, Vec<(ShieldedTokenType, u128)>> = BTreeMap::new();
    for (token, need, segment) in deficits {
        by_segment.entry(segment).or_default().push((token, need));
    }

    // The signer clones the tree fresh per segment, so a coin planned for one segment must not be
    // planned for another; thread the remaining coins across segments to keep the plans disjoint.
    // Also skip coins whose nullifier the transaction already spends — a top-up must not double-spend.
    let already_spent = spent_shielded_nullifiers(base);
    let mut remaining: Vec<QualifiedInfo> = tree
        .coins
        .iter()
        .filter(|(nul, _)| !already_spent.contains(nul))
        .map(|(_nul, qci)| *qci.deref())
        .collect();
    let mut plans = Vec::new();
    for (segment, seg_deficits) in by_segment {
        let seg_plan = plan_shielded_inputs(&remaining, &seg_deficits)?;
        if seg_plan.coins.is_empty() {
            continue;
        }
        remaining.retain(|c| !seg_plan.coins.contains(c));
        let mut change = seg_plan.change_by_token;
        change.extend(claims.remove(&segment).unwrap_or_default());
        plans.push(ShieldedSpendPlan {
            segment,
            coins: seg_plan.coins,
            change,
        });
    }
    plans.extend(
        claims
            .into_iter()
            .map(|(segment, change)| ShieldedSpendPlan {
                segment,
                coins: Vec::new(),
                change,
            }),
    );
    if plans.is_empty() {
        return Ok(None);
    }
    Ok(Some(ShieldedFundingPlan { plans, tree }))
}

/// One intent's fallible unshielded offer the wallet rebuilds: the segment it sits in, the per-token
/// amounts the wallet must supply there (none when it only claims a surplus), and the outputs the
/// replacement carries — the offer's own, re-emitted, plus the wallet's surplus claims.
struct FallibleUnshieldedDeficit {
    seg_id: u16,
    needs: Vec<(UnshieldedTokenType, u128)>,
    outputs: Vec<UtxoOutput>,
}

/// Build the local [`Prover`](crate::Prover) for a chain's vault-rooted proving-key directory.
/// Keyless: the prover holds proving/verifier keys, never a wallet secret. A fresh one is built per
/// authorized section so their proving randomness is independent.
pub(crate) fn midnight_prover(chain_id: &str) -> Result<crate::Prover, std::io::Error> {
    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };
    let dir = crate::cache_io::proving_keys_dir(&scope)
        .ok_or_else(|| err("could not resolve the Midnight proving-key directory"))?;
    Ok(crate::Prover::new(dir))
}

/// Whether the wallet adds a DUST fee section: only when fees are requested, and only on a live-DUST
/// chain. When fees are requested but liveness can't be confirmed, fail loud rather than silently emit
/// a fee-less tx the node would reject — the probe is fail-safe and cannot tell a genuinely fee-less
/// network from a flaky probe, so on a fee-less network the caller opts out with `payFees: false`.
pub(crate) fn adding_dust(pay_fees: bool, indexer_url: &str) -> Result<bool, std::io::Error> {
    if !pay_fees {
        return Ok(false);
    }
    if crate::block_on(crate::wallet_sync::dust::dust_ledger_is_live(indexer_url)) {
        Ok(true)
    } else {
        Err(err(
            "could not confirm the network's DUST ledger is live; refusing to build a fee-less \
             transaction the node may reject — retry, or pass payFees:false if this network has no \
             DUST fees",
        ))
    }
}

/// Reject a transaction whose ledger network id does not match the chain we're signing for, so a
/// mainnet tx can never be balanced/signed while pointed at a testnet (or an ad-hoc feature testnet
/// at another). Matched case-insensitively: a Midnight tx body may carry a capitalized network name.
fn ensure_tx_network_id_matches_chain(
    chain_id: &str,
    tx_network_id: &str,
) -> Result<(), std::io::Error> {
    let expected = MidnightNetwork::from_chain_id(chain_id);
    let expected = expected.ledger_network_id();
    if !tx_network_id.eq_ignore_ascii_case(expected) {
        return Err(err(format!(
            "transaction network id {tx_network_id:?} does not match chain {chain_id} \
             (expected {expected:?})"
        )));
    }
    Ok(())
}

/// Plan (but do not authorize) the balancing of an already-proven (`proof,embedded-fr`) unsealed
/// Standard transaction: parse it, plan the wallet's shielded funding, build the balanced unshielded
/// offer, and size the DUST fee — all without real proving. The returned [`BalancedPlan`] carries no
/// bearer instrument; the authorizing `spend()`/`prove()` happen later, in the signer, past the seam.
#[allow(clippy::too_many_arguments)]
fn plan_unsealed_proven_standard_tx(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    sender_vk: &VerifyingKey,
    sender_addr: &str,
    tx_bytes: &[u8],
    pay_fees: bool,
    scope: &SyncCacheScope,
) -> Result<BalancedPlan, std::io::Error> {
    let mut r: &[u8] = tx_bytes;
    let tx: TxProven = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse proven tx bytes: {e}")))?;
    let Transaction::Standard(mut base) = tx else {
        // The only other Transaction variant is ClaimRewards — a system-issued mint claim that is
        // claimed, not balanced with counter-offers, so it is not a balancing target.
        return Err(err(
            "balanceUnsealedTransaction expects a Standard transaction; a ClaimRewards mint claim \
             is not a balancing target",
        ));
    };

    if let Some(chain_id) = scope.chain_id.as_deref() {
        ensure_tx_network_id_matches_chain(chain_id, &base.network_id)?;
    }

    // Claim every surplus for the wallet, then plan a shielded deficit against the wallet's own shielded
    // coins together with the shielded claims — a no-op when ledger `balance()` has neither. Pure
    // selection: no spend, no prove.
    let claims = surplus_claims(
        &Transaction::Standard(base.clone()),
        UserAddress::from(sender_vk.clone()),
    )?;
    let shielded =
        plan_shielded_funding(&base, crypto_provider, indexer_url, scope, claims.shielded)?;

    // The guaranteed unshielded section aggregates one offer from each intent, so balancing spans every
    // intent: take the negative unshielded cells from ledger `balance()` (NIGHT and custom tokens;
    // mints/withdrawals net positive and are claimed instead), reject shapes the wallet cannot authorize, and
    // fold its inputs + change into a single chosen intent (the lowest segment) while leaving the
    // others intact.
    let adding_dust = adding_dust(pay_fees, indexer_url)?;
    let wallet_dust_address = crypto_provider
        .dust_public_key()
        .map_err(|e| err(e.to_string()))?;
    let mut fallible_outputs_by_seg: BTreeMap<u16, Vec<UtxoOutput>> = BTreeMap::new();
    let mut has_preexisting_dust = false;
    let mut chosen: Option<(
        u16,
        Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    )> = None;
    for pair in base.intents.iter() {
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let intent = intent_sp.deref();
        // A dust section the tx already carries is fine — the wallet's own dust rides a fresh intent
        // below, since an intent holds only one dust section (spec §L961-967). But it must not carry a
        // dust *registration*: unlike a proof-authorized dust *spend* (which passes through untouched), a
        // registration is signature-authorized, so a foreign one needs a signer the wallet lacks, and one
        // for the wallet's own key is redundant with the dust the wallet adds here and muddies the fee
        // accounting. Without dust of the wallet's own, a registration of its NIGHT to its own dust
        // address is the only kind it signs.
        if let Some(da) = intent.dust_actions.as_ref() {
            has_preexisting_dust = true;
            if adding_dust && !da.deref().registrations.is_empty() {
                return Err(err(
                    "transaction already carries a dust fee registration, which is unsupported",
                ));
            }
            for reg in da.deref().registrations.iter() {
                check_carried_registration(&reg, sender_vk, &wallet_dust_address)?;
            }
        }
        if let Some(offer_sp) = intent.guaranteed_unshielded_offer.as_ref() {
            let offer = offer_sp.deref();
            // The wallet supplies (and signs) the balancing inputs; it cannot sign inputs the dapp put
            // in an intent, so reject any that are already present.
            if offer.inputs.iter_deref().next().is_some() {
                return Err(err(
                    "transaction carries dapp-provided unshielded inputs, which is unsupported",
                ));
            }
        }
        // A fallible unshielded offer is balanced in its own segment (each is checked independently).
        // Capture its outputs for re-emit when that segment has a deficit; reject dapp-provided inputs.
        if let Some(foffer_sp) = intent.fallible_unshielded_offer.as_ref() {
            let foffer = foffer_sp.deref();
            if foffer.inputs.iter_deref().next().is_some() {
                return Err(err(
                    "transaction carries dapp-provided fallible unshielded inputs, which is unsupported",
                ));
            }
            fallible_outputs_by_seg.insert(seg_id, fallible_outputs_of(intent));
        }
        let is_lower = match &chosen {
            Some((s, _)) => seg_id < *s,
            None => true,
        };
        if is_lower {
            chosen = Some((seg_id, intent.clone()));
        }
    }

    // Negative unshielded cells from the ledger — the amounts the wallet must supply, already net of
    // contract mints/withdrawals. Segment 0 aggregates the guaranteed section; each fallible segment
    // is funded on its own intent. Positive cells are the surplus claims above.
    let mut guaranteed_needs: BTreeMap<UnshieldedTokenType, u128> = BTreeMap::new();
    let mut fallible_needs: BTreeMap<u16, BTreeMap<UnshieldedTokenType, u128>> = BTreeMap::new();
    for (token, need, segment) in ledger_unshielded_deficits(&Transaction::Standard(base.clone()))?
    {
        if segment == 0 {
            add_u128(&mut guaranteed_needs, token, need);
        } else {
            add_u128(fallible_needs.entry(segment).or_default(), token, need);
        }
    }
    let guaranteed_deficits: Vec<(UnshieldedTokenType, u128)> =
        guaranteed_needs.into_iter().collect();
    // A fallible segment is rebuilt when it is short or carries a surplus to claim.
    let mut fallible_claims = claims.fallible;
    let fallible_segments: BTreeSet<u16> = fallible_needs
        .keys()
        .chain(fallible_claims.keys())
        .copied()
        .collect();
    let fallible_deficits: Vec<FallibleUnshieldedDeficit> = fallible_segments
        .into_iter()
        .map(|seg_id| {
            let mut outputs = fallible_outputs_by_seg.remove(&seg_id).unwrap_or_default();
            outputs.extend(fallible_claims.remove(&seg_id).unwrap_or_default());
            FallibleUnshieldedDeficit {
                seg_id,
                needs: fallible_needs
                    .remove(&seg_id)
                    .map(|needs| needs.into_iter().collect())
                    .unwrap_or_default(),
                outputs,
            }
        })
        .collect();

    // Where the wallet folds its balancing inputs + dust: an existing intent when there is one to reuse,
    // else a fresh skeleton — a shielded-only transaction has empty intents, and a preexisting dust
    // section blocks reuse (see `balancing_intent`).
    let (seg_id, intent_in, mut outputs_in) =
        balancing_intent(&base, chosen, adding_dust, has_preexisting_dust)?;
    outputs_in.extend(claims.guaranteed);

    // Fetch the wallet's UTXOs once; the guaranteed offer and each per-segment fallible offer draw
    // disjoint coins from this pool so no coin is spent twice.
    let pool = crate::block_on(
        crate::wallet_sync::unshielded::get_unshielded_utxos_for_display(
            indexer_url,
            sender_addr,
            scope,
        ),
    )?;
    let mut claimed: Vec<UtxoKey> = Vec::new();

    // When paying a DUST fee, fetch the chain tip up front so the best-Dust NIGHT coin can be reserved
    // for the generationless registration before the balancing inputs are selected. Reusing this tip
    // in the dust-sizing block below keeps it to a single fetch.
    let dust_tip = if adding_dust {
        Some(crate::block_on(crate::ledger_params::fetch_indexer_tip(
            indexer_url,
        ))?)
    } else {
        None
    };
    let registration_reserve = match &dust_tip {
        Some((_, tip_secs)) => {
            fee_sizing::pick_best_unregistered_for_dust(&pool, Timestamp::from_secs(*tip_secs))?
        }
        None => None,
    };

    let (offer, selected) = build_unshielded_balancing_offer(
        &pool,
        &mut claimed,
        sender_vk,
        sender_addr,
        &guaranteed_deficits,
        outputs_in,
        registration_reserve.as_ref(),
    )?;

    // Fund each fallible unshielded deficit in its own segment from the same (now-partly-claimed) pool.
    let mut fallible_offers: Vec<(u16, UnshieldedOffer<MnSig, InMemoryDB>)> = Vec::new();
    for fd in &fallible_deficits {
        let (foffer, _fselected) = build_unshielded_balancing_offer(
            &pool,
            &mut claimed,
            sender_vk,
            sender_addr,
            &fd.needs,
            fd.outputs.clone(),
            None,
        )?;
        fallible_offers.push((fd.seg_id, foffer));
    }

    // On DUST-fee chains, rotate the wallet's remaining unregistered NIGHT (beyond the coin reserved
    // for the registration) onto a fresh fallible segment: consolidate it into a single self-output so
    // it is spent off the budget-tight guaranteed section. Balance-neutral (inputs equal the one
    // change output), so it cannot unbalance the transaction; gated on a reservation existing and at
    // least two leftover coins to fold.
    if adding_dust && registration_reserve.is_some() {
        let night_wire = crate::parse_token_type(Some("night"))?.to_wire_token_type();
        let leftovers: Vec<UnshieldedUtxo> = pool
            .iter()
            .filter(|u| !claimed.contains(&(u.intent_hash.clone(), u.output_index)))
            .filter(|u| !u.registered_for_dust_generation)
            .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
            .cloned()
            .collect();
        // A fresh segment distinct from every existing intent and the chosen balancing segment. The
        // consolidation is optional, so a transaction that leaves no free segment goes without it.
        let seg = fresh_segment_id(&base)
            .ok()
            .zip(seg_id.checked_add(1))
            .map(|(fresh, after_balancing)| fresh.max(after_balancing));
        if let Some(seg) = seg.filter(|_| leftovers.len() >= 2) {
            let coffer = build_fallible_consolidation_offer(
                &leftovers,
                &mut claimed,
                sender_vk,
                sender_addr,
            )?;
            let tip_secs = dust_tip.as_ref().map(|(_, t)| *t).unwrap_or(0);
            let mut consolidation_intent = empty_intent_skeleton();
            consolidation_intent.fallible_unshielded_offer = Some(Sp::new(coffer));
            consolidation_intent.ttl = chain_aligned_intent_ttl(Timestamp::from_secs(tip_secs));
            insert_new_intent(&mut base, seg, consolidation_intent)?;
        }
    }

    // Size the DUST fee against a stand-in tx that already carries the shielded section (mock-proved,
    // fixed-size) and the fallible balancing offers, so the fee — which covers the whole tx — is right
    // even though the real shielded proving is deferred past the seam.
    let mut stx_for_sizing = match &shielded {
        Some(s) => fee_sizing::splice_mock_shielded_for_sizing(&base, crypto_provider, s)?,
        None => base.clone(),
    };
    for (seg, foffer) in &fallible_offers {
        attach_fallible_offer(&mut stx_for_sizing, *seg, foffer);
    }
    // The chosen intent is rebuilt (guaranteed offer + dust) during sizing and authorization, so its
    // own fallible offer, if any, must be threaded into that rebuild rather than left where the rebuild
    // would drop it.
    let chosen_fallible = fallible_offers
        .iter()
        .find(|(s, _)| *s == seg_id)
        .map(|(_, o)| o.clone());

    // On a chain with a live dust ledger (Preview/Preprod, mainnet too), fees are paid with a DUST
    // section: a generationless registration signed by the wallet (no proof) when it has unregistered
    // NIGHT, otherwise a proof-bearing spend of its generated dust. Both that section and an
    // hour-past-tip TTL need the chain time, so fetch the tip once (it also carries the ledger
    // parameters used to size the fee). The fee is sized here without real proving; the proof-bearing
    // spend is realized post-seam by the signer.
    let (dust, intent_ttl) = if adding_dust {
        let (ledger_params, tip_secs) = dust_tip.expect("dust tip fetched above when adding_dust");
        let dust_ctime = Timestamp::from_secs(tip_secs);
        let dust_pk = crypto_provider
            .dust_public_key()
            .map_err(|e| err(e.to_string()))?;
        let night_vk = sender_vk.clone();
        fee_sizing::size_dust_fee(&DustFeeContext {
            stx: &stx_for_sizing,
            seg_id,
            intent_in: &intent_in,
            offer: &offer,
            fallible_offer: chosen_fallible.as_ref(),
            selected: &selected,
            dust_pk,
            night_vk,
            crypto_provider,
            dust_ctime,
            ledger_params: &ledger_params,
            indexer_url,
            scope,
        })?
    } else {
        (DustFeePlan::None, intent_in.ttl)
    };

    Ok(BalancedPlan {
        base,
        seg_id,
        intent_in,
        unshielded_offer: offer,
        fallible_offers,
        intent_ttl,
        shielded,
        dust,
    })
}

/// Authorize a [`BalancedPlan`] into balanced-but-unsealed proven transaction bytes. The wallet's
/// shielded/dust spend witnesses are built and proved **in the signer** — this hands the
/// `crypto_provider` its [`MidnightCryptoProvider::authorize_shielded`] / `authorize_dust` methods,
/// which build and consume the bearer preimage internally; only proven sections cross back. So this
/// runs **after** the policy seam. The proven shielded fragments are merged into the guaranteed offer
/// (folding in their binding-randomness delta, since a proven tx can't recompute its own Pedersen
/// binding) and the DUST section attached; the tx is then serialized. Signing and sealing are separate
/// downstream steps.
pub fn authorize_proven_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    plan: BalancedPlan,
) -> Result<Vec<u8>, std::io::Error> {
    let mut base = plan.base;

    // Shielded: the signer builds + proves the witnesses; route each proven fragment to the offer the
    // signer bound it to — segment 0 into the guaranteed offer, segment N>=1 into `fallible_coins[N]`.
    if let Some(shielded) = plan.shielded {
        let prover = midnight_prover(chain_id)?;
        let authorized: ShieldedAuthorized = crate::block_on(crypto_provider.authorize_shielded(
            &shielded.plans,
            &shielded.tree,
            prover,
        ))
        .map_err(|e| err(e.to_string()))?;
        for (segment, proven) in &authorized.proven {
            place_shielded_fragment(&mut base, *segment, proven)?;
        }
        // Binding randomness is tx-global (placement-independent), so add the whole delta once.
        base.binding_randomness = base.binding_randomness + authorized.binding_delta;
    }

    // DUST: the registration was finalized during planning (keyless, no bearer instrument); the
    // proof-bearing spend is realized here, in the signer.
    let dust_actions = match plan.dust {
        DustFeePlan::None => None,
        DustFeePlan::Registration(reg) => Some(reg),
        DustFeePlan::Spend {
            plan: dust_plan,
            dust_state,
            ledger_params,
        } => {
            let prover = midnight_prover(chain_id)?;
            let section = crate::block_on(crypto_provider.authorize_dust(
                &dust_state,
                &dust_plan,
                &ledger_params,
                prover,
            ))
            .map_err(|e| err(e.to_string()))?;
            Some(section)
        }
    };

    // Fallible unshielded offers: attach each to the intent in its own segment. The chosen intent is
    // rebuilt just below (guaranteed offer + dust), so its fallible offer is threaded into that rebuild
    // instead; every other fallible offer is attached here directly.
    let chosen_fallible = plan
        .fallible_offers
        .iter()
        .find(|(s, _)| *s == plan.seg_id)
        .map(|(_, o)| o.clone());
    for (seg, foffer) in &plan.fallible_offers {
        if *seg != plan.seg_id {
            attach_fallible_offer(&mut base, *seg, foffer);
        }
    }

    let intent_out = assemble_proven_intent(
        &plan.unshielded_offer,
        chosen_fallible.as_ref(),
        &plan.intent_in,
        dust_actions,
        plan.intent_ttl,
    );
    let tx_out = wrap_proven_standard(&base, plan.seg_id, intent_out);

    let imbalances = tx_balance_imbalances(&tx_out)?;
    if !imbalances.is_empty() {
        return Err(err(format!(
            "authorized transaction is still ledger-imbalanced ({})",
            imbalances.join("; ")
        )));
    }

    let mut out = Vec::new();
    tagged_serialize(&tx_out, &mut out).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(out)
}

/// Plan the balancing of an already-proven (`proof,embedded-fr`) unsealed connector transaction
/// against the wallet's own UTXOs, deriving the sender address/vk via the crypto provider and the
/// indexer URL and sync scope from `chain_id`. The returned [`BalancedPlan`] is inert (no bearer
/// instrument) — it is authorized into signable bytes by [`authorize_proven_tx`] after the policy seam.
pub fn plan_unsealed_proven_tx(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    tx_bytes: &[u8],
    pay_fees: bool,
) -> Result<BalancedPlan, std::io::Error> {
    let sender_addr = crypto_provider
        .addresses(&MidnightNetwork::from_chain_id(chain_id))
        .map_err(|e| err(e.to_string()))?
        .unshielded;
    let sender_vk = crypto_provider
        .unshielded_verifying_key()
        .map_err(|e| err(e.to_string()))?;

    let indexer_url = crate::wallet::resolve_indexer_url(chain_id)?;

    let scope = SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        ..Default::default()
    };

    plan_unsealed_proven_standard_tx(
        &indexer_url,
        crypto_provider,
        &sender_vk,
        &sender_addr,
        tx_bytes,
        pay_fees,
        &scope,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenType;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_base_crypto::signatures::SigningKey as MidnightSigningKey;
    use midnight_base_crypto::time::Timestamp;
    use midnight_ledger::dust::{DustActions, DustPublicKey, DustRegistration, DustSecretKey};
    use midnight_ledger::structure::IntentHash;
    use ows_signer::chains::MidnightSigner;
    use ows_signer::traits::ChainSigner;
    use ows_signer::SecretBytes;
    use transient_crypto::commitment::PureGeneratorPedersen;

    // Unshielded role-0 seed for the abandon-phrase wallet at index 0; matches the signer's
    // address vectors. A second valid seed drives the wrong-owner test.
    const UNSHIELDED_SEED_HEX: &str =
        "822fa63c57f6317cd51d12d80f0e64c2bc2164088dec1c71ca34a87a890190aa";
    const OTHER_SEED_HEX: &str = "92933dd3dff04c57c9f8950d6e08bd5c6f295655c03627a658e09b0726558cad";

    /// Pack a Midnight signing key the way `secret_to_signing_key` does: the `MNK1` magic followed
    /// by three 32-byte role seeds. Signing uses the unshielded seed, plus the dust seed (`0x22`) to
    /// check a registration targets the wallet's own dust address; the shielded slot is filler.
    fn packed_signing_key(unshielded_seed_hex: &str) -> SecretBytes {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&hex::decode(unshielded_seed_hex).unwrap());
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        SecretBytes::new(blob)
    }

    /// A generationless dust fee registration owned by `vk` — the signature-based (no-proof) fee
    /// path — to the dust address of [`packed_signing_key`]'s dust seed, the only target it signs.
    fn dust_fee_registration(vk: &VerifyingKey) -> DustActions<MnSig, ProofMarker, InMemoryDB> {
        dust_registration_to(vk, Some(own_dust_address()))
    }

    /// The dust address of [`packed_signing_key`]'s dust seed.
    fn own_dust_address() -> DustPublicKey {
        DustPublicKey::from(DustSecretKey::derive_secret_key(&[0x22u8; 32]))
    }

    /// A dust registration of `vk`'s NIGHT to `dust_address` (`None` deregisters).
    fn dust_registration_to(
        vk: &VerifyingKey,
        dust_address: Option<DustPublicKey>,
    ) -> DustActions<MnSig, ProofMarker, InMemoryDB> {
        DustActions {
            spends: vec![].into(),
            registrations: vec![DustRegistration {
                night_key: vk.clone(),
                dust_address: dust_address.map(Sp::new),
                allow_fee_payment: 100_000,
                signature: None,
            }]
            .into(),
            ctime: Timestamp::from_secs(0),
        }
    }

    /// Build a minimal proven (`proof,embedded-fr`) unsealed Standard tx: one guaranteed unshielded
    /// NIGHT input owned by `vk` plus a matching output, no contract calls / shielded coins, and the
    /// given optional dust actions. Structurally what the balancer emits, so it exercises sign →
    /// reattach → seal without a prover or indexer.
    fn build_proven_unshielded_tx(
        vk: &VerifyingKey,
        dust_actions: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ) -> Vec<u8> {
        let input = UtxoSpend {
            value: 1_000_000,
            owner: vk.clone(),
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([7u8; 32])),
            output_no: 0,
        };
        let output = UtxoOutput {
            value: 1_000_000,
            owner: UserAddress::from(vk.clone()),
            type_: NIGHT,
        };
        let offer = UnshieldedOffer {
            inputs: vec![input].into(),
            outputs: vec![output].into(),
            signatures: vec![].into(),
        };
        let intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(offer)),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: dust_actions.map(Sp::new),
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(0, intent);
        let stx = StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        };
        let tx: TxProven = Transaction::Standard(stx);
        let mut out = Vec::new();
        tagged_serialize(&tx, &mut out).unwrap();
        out
    }

    #[test]
    fn adding_dust_refuses_when_liveness_cannot_be_confirmed() {
        let unreachable = "http://127.0.0.1:1/api/v3/graphql";
        assert!(!adding_dust(false, unreachable).unwrap());
        let e = adding_dust(true, unreachable).unwrap_err();
        assert!(e.to_string().contains("DUST ledger is live"), "{e}");
    }

    #[test]
    fn a_message_signature_over_data_to_sign_does_not_authorize_the_intent() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, None);
        let mut r: &[u8] = tx_bytes.as_slice();
        let Transaction::Standard(stx) = tagged_deserialize::<TxProven>(&mut r).unwrap() else {
            panic!("standard");
        };
        let pair = stx.intents.iter().next().unwrap();
        let (seg_sp, intent_sp) = pair.deref();
        let data = intent_sp
            .deref()
            .clone()
            .erase_proofs()
            .erase_signatures()
            .data_to_sign(*seg_sp.deref());

        let authorized = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        let authorized = MnSig::deserialize(&mut &authorized.signature[..], 0).unwrap();
        assert!(vk.verify(&data, &authorized));

        // The same key asked to sign those bytes as a message frames them first, so the result
        // is not a signature over the intent.
        let message = signer.sign_message(key.expose(), &data, None).unwrap();
        let message = MnSig::deserialize(&mut &message.signature[..], 0).unwrap();
        assert!(!vk.verify(&data, &message));
    }

    #[test]
    fn sign_then_encode_seals_a_tx_carrying_a_valid_signature() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, None);

        // Sign: one detached signature over the intent's signing message, no seal.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        assert!(!out.signature.is_empty(), "expected a signature blob");

        // It verifies against the intent's data_to_sign for the input owner — i.e. the detached
        // step really signs the message the ledger's own Intent::sign would.
        let mut r: &[u8] = tx_bytes.as_slice();
        let parsed: TxProven = tagged_deserialize(&mut r).unwrap();
        let Transaction::Standard(stx) = parsed else {
            panic!("standard");
        };
        let pair = stx.intents.iter().next().unwrap();
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let intent = intent_sp.deref().clone();
        let data = intent
            .erase_proofs()
            .erase_signatures()
            .data_to_sign(seg_id);
        let sig = MnSig::deserialize(&mut &out.signature[..], 0).unwrap();
        assert!(
            vk.verify(&data, &sig),
            "signature must verify over data_to_sign"
        );

        // Encode: reattach + seal (keyless). The sealed Standard tx's guaranteed offer now carries
        // the signature.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut r2: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut r2).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let sealed_pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, sealed_intent_sp) = sealed_pair.deref();
        let sig_count = sealed_intent_sp
            .deref()
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(sig_count, 1, "sealed tx should carry exactly one signature");
    }

    #[test]
    fn sign_rejects_a_tx_whose_inputs_it_does_not_own() {
        let signer = MidnightSigner::mainnet();
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, None);

        // Sign the same tx with a different wallet key — the ownership check must reject it.
        let wrong_key = packed_signing_key(OTHER_SEED_HEX);
        let err = signer
            .sign_transaction(wrong_key.expose(), &tx_bytes)
            .unwrap_err();
        assert!(
            format!("{err}").contains("owned by the signing key"),
            "unexpected error: {err}"
        );
    }

    /// A registration to another dust address, or a deregistration, would hand off or switch off the
    /// wallet's DUST generation, so the signer refuses both, whatever the balancer let through.
    #[test]
    fn sign_refuses_a_registration_away_from_the_wallets_own_dust_address() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let elsewhere = DustPublicKey::from(DustSecretKey::derive_secret_key(&[0x33u8; 32]));

        for (dust_address, expected) in [
            (Some(elsewhere), "another dust address"),
            (None, "dust deregistration"),
        ] {
            let tx_bytes =
                build_proven_unshielded_tx(&vk, Some(dust_registration_to(&vk, dust_address)));
            let err = signer
                .sign_transaction(key.expose(), &tx_bytes)
                .unwrap_err();
            assert!(
                format!("{err}").contains(expected),
                "unexpected error: {err}"
            );
        }
    }

    /// The balancer applies the signer's rule to every registration the dapp's transaction carries,
    /// so a bad one fails before anything is proven.
    #[test]
    fn a_carried_registration_must_target_the_wallets_own_dust_address() {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let other_vk = MidnightSigningKey::from_bytes(&hex::decode(OTHER_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let own = own_dust_address();
        let elsewhere = DustPublicKey::from(DustSecretKey::derive_secret_key(&[0x33u8; 32]));
        let check = |night_key: &VerifyingKey, dust_address: Option<DustPublicKey>| {
            let da = dust_registration_to(night_key, dust_address);
            let reg = da.registrations.iter().next().unwrap();
            check_carried_registration(&reg, &vk, &own)
        };

        assert!(check(&vk, Some(own)).is_ok());
        for (night_key, dust_address, expected) in [
            (&vk, Some(elsewhere), "another dust address"),
            (&vk, None, "deregistration"),
            (&other_vk, Some(own), "another NIGHT key"),
        ] {
            let msg = check(night_key, dust_address).unwrap_err().to_string();
            assert!(msg.contains(expected), "{msg}");
        }
    }

    #[test]
    fn sign_then_encode_signs_the_dust_fee_registration() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_unshielded_tx(&vk, Some(dust_fee_registration(&vk)));

        // Sign: one signature for the input plus one for the dust fee registration.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        let mut r: &[u8] = &out.signature[..];
        let sig_a = MnSig::deserialize(&mut r, 0).unwrap();
        let sig_b = MnSig::deserialize(&mut r, 0).unwrap();
        assert!(r.is_empty(), "expected exactly two signatures");

        // Both verify against the intent's data_to_sign.
        let mut tr: &[u8] = tx_bytes.as_slice();
        let parsed: TxProven = tagged_deserialize(&mut tr).unwrap();
        let Transaction::Standard(stx) = parsed else {
            panic!("standard");
        };
        let pair = stx.intents.iter().next().unwrap();
        let (seg_sp, intent_sp) = pair.deref();
        let seg_id = *seg_sp.deref();
        let data = intent_sp
            .deref()
            .clone()
            .erase_proofs()
            .erase_signatures()
            .data_to_sign(seg_id);
        assert!(vk.verify(&data, &sig_a) && vk.verify(&data, &sig_b));

        // Seal: the sealed tx's dust registration carries a signature, and the offer has one too.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut sr: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut sr).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let sealed_pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, sealed_intent_sp) = sealed_pair.deref();
        let sealed_intent = sealed_intent_sp.deref();
        let reg_signed = sealed_intent
            .dust_actions
            .as_ref()
            .and_then(|da| da.deref().registrations.iter().next())
            .map(|reg| reg.signature.is_some())
            .unwrap_or(false);
        assert!(reg_signed, "sealed dust registration must be signed");
        let offer_sigs = sealed_intent
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(offer_sigs, 1, "the input signature stays on the offer");
    }

    /// A synced coin of the given token and value; the nonce/mt_index don't affect selection.
    fn qci(token: ShieldedTokenType, value: u128) -> QualifiedInfo {
        use rand::Rng as _;
        let mut coin: QualifiedInfo = rand::rngs::OsRng.r#gen();
        coin.type_ = token;
        coin.value = value;
        coin
    }

    /// Whole coins are spent largest-first until the deficit is covered; the excess becomes self-change
    /// and unneeded coins are left untouched. No spend/prove — pure selection.
    #[test]
    fn plan_shielded_inputs_selects_largest_first_and_sizes_change() {
        let token = ShieldedTokenType(HashOutput([7u8; 32]));
        let coins = vec![qci(token, 100), qci(token, 30), qci(token, 40)];
        // Need 120: 100 then 40 (= 140) covers it; the 30-coin is untouched. Change = 20.
        let plan = plan_shielded_inputs(&coins, &[(token, 120)]).unwrap();
        let picked: Vec<u128> = plan.coins.iter().map(|c| c.value).collect();
        assert_eq!(picked, vec![100, 40]);
        assert_eq!(plan.change_by_token, vec![(token, 20)]);
    }

    /// A token whose coins can't cover its deficit errors before any spend/prove.
    #[test]
    fn plan_shielded_inputs_errors_when_coins_fall_short() {
        let token = ShieldedTokenType(HashOutput([3u8; 32]));
        let coins = vec![qci(token, 10), qci(token, 5)];
        let e = plan_shielded_inputs(&coins, &[(token, 100)]).unwrap_err();
        assert!(
            format!("{e}").contains("insufficient shielded balance"),
            "unexpected error: {e}"
        );
    }

    /// A zero deficit selects nothing; an exact-cover selection yields no change.
    #[test]
    fn plan_shielded_inputs_zero_and_exact_yield_no_change() {
        let token = ShieldedTokenType(HashOutput([2u8; 32]));
        let coins = vec![qci(token, 500)];
        let zero = plan_shielded_inputs(&coins, &[(token, 0)]).unwrap();
        assert!(zero.coins.is_empty() && zero.change_by_token.is_empty());
        let exact = plan_shielded_inputs(&coins, &[(token, 500)]).unwrap();
        assert_eq!(exact.coins.len(), 1);
        assert!(exact.change_by_token.is_empty());
    }

    /// An empty unshielded offer (no inputs/outputs/signatures) — a placeholder for tests that only
    /// exercise intent structure, not balancing.
    fn empty_offer() -> UnshieldedOffer<MnSig, InMemoryDB> {
        UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![].into(),
            signatures: vec![].into(),
        }
    }

    /// A proven intent carrying `offer` as its guaranteed offer plus optional dust, at a **nonzero**
    /// binding commitment so tests can observe whether it is perturbed.
    fn intent_with(
        offer: Option<UnshieldedOffer<MnSig, InMemoryDB>>,
        dust: Option<DustActions<MnSig, ProofMarker, InMemoryDB>>,
    ) -> Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
        Intent {
            guaranteed_unshielded_offer: offer.map(Sp::new),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: dust.map(Sp::new),
            ttl: Timestamp::from_secs(0),
            binding_commitment: PedersenRandomness::from(7),
        }
    }

    fn base_with_intents(
        intents: Vec<(
            u16,
            Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
        )>,
    ) -> StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> {
        let mut map: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new();
        for (seg, intent) in intents {
            map = map.insert(seg, intent);
        }
        StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents: map,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: PedersenRandomness::from(0),
        }
    }

    fn wallet_vk() -> VerifyingKey {
        MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key()
    }

    /// An unshielded offer spending one `value` coin of `token` owned by `vk`, with `outputs`.
    fn spend_offer(
        vk: &VerifyingKey,
        token: UnshieldedTokenType,
        value: u128,
        outputs: Vec<UtxoOutput>,
    ) -> UnshieldedOffer<MnSig, InMemoryDB> {
        UnshieldedOffer {
            inputs: vec![UtxoSpend {
                value,
                owner: vk.clone(),
                type_: token,
                intent_hash: IntentHash(HashOutput([9u8; 32])),
                output_no: 0,
            }]
            .into(),
            outputs: outputs.into(),
            signatures: vec![].into(),
        }
    }

    fn no_positive_cells(
        base: &StandardTransaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>,
    ) -> bool {
        Transaction::Standard(base.clone())
            .balance(None)
            .unwrap()
            .values()
            .all(|bal| *bal <= 0)
    }

    /// Spending 1 000 000 NIGHT and keeping 400 000 leaves 600 000 that no output receives: the
    /// ledger would fail it on the NIGHT supply check. The wallet claims exactly that, as an output
    /// to itself in the guaranteed section, and the claim nets it to zero.
    #[test]
    fn claims_a_guaranteed_night_surplus() {
        let spender = wallet_vk();
        let keep = UtxoOutput {
            value: 400_000,
            owner: UserAddress::from(spender.clone()),
            type_: NIGHT,
        };
        let offer = spend_offer(&spender, NIGHT, 1_000_000, vec![keep]);
        let mut base = base_with_intents(vec![(1, intent_with(Some(offer), None))]);
        let wallet = UserAddress::from(
            MidnightSigningKey::from_bytes(&[0x33; 32])
                .unwrap()
                .verifying_key(),
        );

        let claims = surplus_claims(&Transaction::Standard(base.clone()), wallet).unwrap();
        let claim = UtxoOutput {
            value: 600_000,
            owner: wallet,
            type_: NIGHT,
        };
        assert_eq!(
            claims,
            SurplusClaims {
                guaranteed: vec![claim],
                ..Default::default()
            }
        );

        // Riding the guaranteed offer, the claim brings segment 0 back to zero.
        let mut intent = base.intents.get(&1).unwrap().deref().clone();
        let mut offer = intent.guaranteed_unshielded_offer.unwrap().deref().clone();
        let mut outputs: Vec<UtxoOutput> = offer.outputs.iter_deref().cloned().collect();
        outputs.extend(claims.guaranteed);
        outputs.sort();
        offer.outputs = outputs.into();
        intent.guaranteed_unshielded_offer = Some(Sp::new(offer));
        base.intents = base.intents.insert(1, intent);
        assert!(no_positive_cells(&base));
        assert!(tx_balance_imbalances(&TxProven::Standard(base))
            .unwrap()
            .is_empty());
    }

    /// A surplus in a fallible segment is claimed in that segment, where it nets.
    #[test]
    fn claims_a_fallible_surplus_in_its_own_segment() {
        let token = UnshieldedTokenType(HashOutput([0x44; 32]));
        let mut intent = intent_with(None, None);
        intent.fallible_unshielded_offer =
            Some(Sp::new(spend_offer(&wallet_vk(), token, 100, vec![])));
        let base = base_with_intents(vec![(2, intent)]);
        let wallet = UserAddress::from(wallet_vk());

        let claims = surplus_claims(&Transaction::Standard(base), wallet).unwrap();
        assert!(claims.guaranteed.is_empty());
        assert_eq!(
            claims.fallible,
            BTreeMap::from([(
                2,
                vec![UtxoOutput {
                    value: 100,
                    owner: wallet,
                    type_: token,
                }]
            )])
        );
    }

    /// A shielded surplus becomes a shielded output to the wallet in its segment. Planning it needs no
    /// coins, so the plan is built without syncing (the indexer here is unreachable), and the output the
    /// provider builds from it really nets the surplus.
    #[test]
    fn claims_a_shielded_surplus_with_a_real_output() {
        use midnight_storage::storage::Array;
        use midnight_zswap::{Delta, Input};
        use std::sync::Arc;
        use transient_crypto::commitment::Pedersen;
        use transient_crypto::curve::Fr;
        use transient_crypto::merkle_tree::MerkleTreeDigest;
        use transient_crypto::proofs::Proof;

        // The transaction spends 100 of a shielded token: one input, no output for it.
        let token = ShieldedTokenType(HashOutput([0x55; 32]));
        let given = ZswapOffer {
            inputs: vec![Input {
                nullifier: Nullifier(HashOutput([0xAB; 32])),
                value_commitment: Pedersen::from(PedersenRandomness::from(0)),
                contract_address: None,
                merkle_tree_root: MerkleTreeDigest::from(Fr::from(0u64)),
                proof: Arc::new(Proof(vec![])),
            }]
            .into(),
            outputs: Array::new(),
            transient: Array::new(),
            deltas: vec![Delta {
                token_type: token,
                value: 100,
            }]
            .into(),
        };
        let mut base = base_with_intents(vec![]);
        base.guaranteed_coins = Some(Sp::new(given));

        let claims = surplus_claims(
            &Transaction::Standard(base.clone()),
            UserAddress::from(wallet_vk()),
        )
        .unwrap();
        assert_eq!(claims.shielded, BTreeMap::from([(0, vec![(token, 100)])]));

        let provider = MidnightSigner::mainnet()
            .crypto_provider(&packed_signing_key(UNSHIELDED_SEED_HEX))
            .unwrap();
        let scope = SyncCacheScope::default();
        let plan = plan_shielded_funding(
            &base,
            &provider,
            "http://127.0.0.1:1/api/v3/graphql",
            &scope,
            claims.shielded,
        )
        .unwrap()
        .expect("a claim plan");
        assert_eq!(plan.plans.len(), 1);
        assert!(plan.plans[0].coins.is_empty());
        assert_eq!(plan.plans[0].change, vec![(token, 100)]);

        let built = provider
            .mock_shielded_offers(&base.network_id, &plan.plans, &plan.tree)
            .unwrap();
        for (segment, offer) in &built.proven {
            assert_eq!(offer.outputs.len(), 1, "one real output to the wallet");
            place_shielded_fragment(&mut base, *segment, offer).unwrap();
        }
        assert!(no_positive_cells(&base));
    }

    /// The fresh segment is one past the current maximum, and 1 when there are no intents — never 0
    /// (reserved for the guaranteed section).
    #[test]
    fn fresh_segment_id_is_one_past_the_max() {
        let base = base_with_intents(vec![
            (2, intent_with(None, None)),
            (5, intent_with(None, None)),
        ]);
        assert_eq!(fresh_segment_id(&base).unwrap(), 6);
        assert_eq!(fresh_segment_id(&base_with_intents(vec![])).unwrap(), 1);
    }

    /// A dapp intent at the last segment leaves no fresh one: the wallet refuses rather than wrap
    /// around onto, and replace, that intent.
    #[test]
    fn fresh_segment_id_refuses_to_wrap_past_the_last_segment() {
        let base = base_with_intents(vec![
            (1, intent_with(None, None)),
            (u16::MAX, intent_with(None, None)),
        ]);
        let msg = fresh_segment_id(&base).unwrap_err().to_string();
        assert!(msg.contains("no free intent segment"), "{msg}");
    }

    /// A new intent never lands on a taken segment, so a dapp's intent there survives.
    #[test]
    fn insert_new_intent_refuses_a_taken_segment() {
        let mut base = base_with_intents(vec![(u16::MAX, intent_with(Some(empty_offer()), None))]);
        let msg = insert_new_intent(&mut base, u16::MAX, empty_intent_skeleton())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("already taken"), "{msg}");
        let kept = base.intents.get(&u16::MAX).unwrap();
        assert!(kept.deref().guaranteed_unshielded_offer.is_some());

        insert_new_intent(&mut base, 1, empty_intent_skeleton()).unwrap();
        assert!(base.intents.contains_key(&1));
    }

    /// The skeleton that carries a wallet dust section onto a fresh segment is empty and
    /// binding-neutral (zero `binding_commitment`), so adding it leaves the tx's `binding_randomness`
    /// untouched.
    #[test]
    fn empty_intent_skeleton_is_empty_and_binding_neutral() {
        let s = empty_intent_skeleton();
        assert_eq!(s.binding_commitment, PedersenRandomness::from(0));
        assert!(s.guaranteed_unshielded_offer.is_none());
        assert!(s.fallible_unshielded_offer.is_none());
        assert!(s.dust_actions.is_none());
        assert_eq!(s.actions.len(), 0);
    }

    /// A shielded-only tx has an **empty** `intents` map, so there is no intent to fold the wallet's
    /// dust fee into. The balancer synthesizes a fresh binding-neutral skeleton at segment 1 rather than
    /// error "expected at least one intent segment".
    #[test]
    fn empty_intents_get_a_fresh_balancing_skeleton() {
        let base = base_with_intents(vec![]);
        let (seg_id, intent_in, outputs_in) = balancing_intent(&base, None, true, false).unwrap();
        assert_eq!(
            seg_id, 1,
            "first fresh segment, never the guaranteed section 0"
        );
        assert!(intent_in.guaranteed_unshielded_offer.is_none());
        assert!(intent_in.dust_actions.is_none());
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(0),
            "a synthesized skeleton is binding-neutral"
        );
        assert!(outputs_in.is_empty());
    }

    /// With a reusable intent and no preexisting dust, the wallet folds into that intent (keeping its
    /// segment and re-emitting its outputs) instead of synthesizing a new one.
    #[test]
    fn balancing_intent_reuses_an_existing_intent() {
        let base = base_with_intents(vec![(3, intent_with(None, None))]);
        let (seg_id, intent_in, _outputs) =
            balancing_intent(&base, Some((3, intent_with(None, None))), true, false).unwrap();
        assert_eq!(seg_id, 3, "reused, not a fresh segment");
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(7),
            "the existing intent, not a fresh skeleton"
        );
    }

    /// A preexisting dust section forces a fresh skeleton even when a reusable intent exists, because an
    /// intent holds only one dust section and the wallet's dust needs its own timestamp.
    #[test]
    fn preexisting_dust_forces_a_fresh_skeleton() {
        let base = base_with_intents(vec![(3, intent_with(None, None))]);
        let (seg_id, intent_in, _outputs) =
            balancing_intent(&base, Some((3, intent_with(None, None))), true, true).unwrap();
        assert_eq!(seg_id, 4, "fresh, one past the existing max segment (3)");
        assert_eq!(
            intent_in.binding_commitment,
            PedersenRandomness::from(0),
            "a fresh skeleton, not the existing intent"
        );
    }

    /// Merging into a dapp intent that already carries its own dust must not drop it when the wallet
    /// supplies no dust of its own; the wallet's dust wins when it does.
    #[test]
    fn assemble_preserves_a_dapp_intents_own_dust() {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let intent_in = intent_with(None, Some(dust_fee_registration(&vk)));

        // No dust of our own → the intent's existing dust survives.
        let kept = assemble_proven_intent(
            &empty_offer(),
            None,
            &intent_in,
            None,
            Timestamp::from_secs(0),
        );
        assert!(
            kept.dust_actions.is_some(),
            "merging must not drop the intent's own dust"
        );

        // Our own dust replaces it when supplied.
        let ours = dust_fee_registration(&vk);
        let replaced = assemble_proven_intent(
            &empty_offer(),
            None,
            &intent_in,
            Some(ours.clone()),
            Timestamp::from_secs(0),
        );
        assert_eq!(
            replaced.dust_actions.as_ref().unwrap().deref().ctime,
            ours.ctime
        );
    }

    /// Placing the wallet's balancing offer at a fresh segment (the Gap C new-intent path) adds an
    /// intent without touching the existing ones or the tx's binding randomness.
    #[test]
    fn wrap_at_a_fresh_segment_adds_without_disturbing_the_rest() {
        let base = base_with_intents(vec![(2, intent_with(Some(empty_offer()), None))]);
        let orig_binding = base.binding_randomness;
        let fresh = fresh_segment_id(&base).unwrap();
        assert_eq!(fresh, 3);

        let new_intent = assemble_proven_intent(
            &empty_offer(),
            None,
            &empty_intent_skeleton(),
            None,
            Timestamp::from_secs(0),
        );
        let Transaction::Standard(stx) = wrap_proven_standard(&base, fresh, new_intent) else {
            panic!("standard");
        };

        let segs: Vec<u16> = stx.intents.iter().map(|p| *p.deref().0.deref()).collect();
        assert_eq!(
            stx.intents.iter().count(),
            2,
            "the original intent survives"
        );
        assert!(segs.contains(&2) && segs.contains(&3));
        assert_eq!(
            stx.binding_randomness, orig_binding,
            "a binding-neutral intent leaves binding_randomness untouched"
        );
    }

    /// The wallet's verifying-key as the lowercase hex the indexer reports for a UTXO owner.
    fn sender_vk_hex() -> String {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let mut raw = Vec::new();
        vk.serialize(&mut raw).unwrap();
        hex::encode(raw)
    }

    /// A sender-owned NIGHT UTXO for the coin pool; `ih_byte` makes each one a distinct coin.
    fn night_pool_utxo(vk_hex: &str, value: u128, ih_byte: u8, out_idx: i64) -> UnshieldedUtxo {
        UnshieldedUtxo {
            token_type: "00".repeat(32),
            value,
            intent_hash: hex::encode([ih_byte; 32]),
            output_index: out_idx,
            owner: vk_hex.to_string(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    /// Two offers drawn from the same pool never spend the same coin: the second call skips the coin the
    /// first claimed.
    #[test]
    fn build_night_offer_claims_disjoint_coins() {
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let vk_hex = sender_vk_hex();
        let pool = vec![
            night_pool_utxo(&vk_hex, 100, 1, 0),
            night_pool_utxo(&vk_hex, 100, 2, 0),
        ];
        let mut claimed: Vec<UtxoKey> = Vec::new();

        let (_o1, s1) =
            build_night_offer(&pool, &mut claimed, &vk, "sender", 60, vec![], None).unwrap();
        let (_o2, s2) =
            build_night_offer(&pool, &mut claimed, &vk, "sender", 60, vec![], None).unwrap();

        assert_eq!(s1.len(), 1);
        assert_eq!(s2.len(), 1);
        assert_ne!(
            s1[0].intent_hash, s2[0].intent_hash,
            "coins must be disjoint"
        );
        assert_eq!(claimed.len(), 2);
    }

    /// With no NIGHT payment (need_night = 0) a reserved best-Dust coin is still spent — so its
    /// unregistered-NIGHT capacity can back the generationless registration — and its value returns
    /// as change, so the offer nets to zero (one input, matching output value).
    #[test]
    fn build_night_offer_reserves_the_dust_coin_balance_neutrally() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        let reserve = night_pool_utxo(&vk_hex, 5_000_000, 7, 0);
        let pool = vec![reserve.clone()];
        let mut claimed = Vec::new();
        let (offer, selected) = build_night_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            0,
            vec![],
            Some(&reserve),
        )
        .unwrap();

        assert_eq!(selected.len(), 1, "the reserved coin is spent");
        assert_eq!(selected[0].intent_hash, reserve.intent_hash);
        assert_eq!(claimed.len(), 1);
        assert_eq!(offer.inputs.iter_deref().count(), 1);
        let out_total: u128 = offer.outputs.iter_deref().map(|o| o.value).sum();
        assert_eq!(
            out_total, reserve.value,
            "change returns the full input value"
        );
    }

    /// A custom unshielded token is funded the same way as NIGHT: whole coins, largest-first, with
    /// change of that same type — and a NIGHT coin in the pool is left untouched.
    #[test]
    fn build_unshielded_balancing_offer_funds_custom_token() {
        use midnight_base_crypto::hash::HashOutput;
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let vk_hex = sender_vk_hex();
        let custom = UnshieldedTokenType(HashOutput([0xab; 32]));
        let custom_wire = unshielded_token_wire(custom);
        let mut custom_utxo = night_pool_utxo(&vk_hex, 100, 1, 0);
        custom_utxo.token_type = custom_wire;
        let pool = vec![
            custom_utxo,
            night_pool_utxo(&vk_hex, 1_000_000, 2, 0), // must not be spent
        ];
        let mut claimed = Vec::new();
        let (offer, selected) = build_unshielded_balancing_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            &[(custom, 60)],
            vec![],
            None,
        )
        .unwrap();

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].token_type, unshielded_token_wire(custom));
        assert_eq!(offer.inputs.iter_deref().count(), 1);
        assert_eq!(offer.inputs.iter_deref().next().unwrap().type_, custom);
        let change: Vec<_> = offer
            .outputs
            .iter_deref()
            .filter(|o| o.type_ == custom)
            .collect();
        assert_eq!(change.len(), 1);
        assert_eq!(change[0].value, 40);
        assert!(
            offer.inputs.iter_deref().all(|i| i.type_ != NIGHT),
            "NIGHT pool coin must stay unspent"
        );
    }

    /// A custom unshielded overspend in a fallible offer shows up as a negative unshielded cell in
    /// ledger `balance()` — the same signal NIGHT uses — so `ledger_unshielded_deficits` reports it.
    #[test]
    fn ledger_unshielded_deficits_reports_custom_token_overspend() {
        use midnight_base_crypto::hash::HashOutput;
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let custom = UnshieldedTokenType(HashOutput([0xcd; 32]));
        let offer = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![UtxoOutput {
                value: 42,
                owner: wallet_ua,
                type_: custom,
            }]
            .into(),
            signatures: vec![].into(),
        };
        let intent = Intent {
            guaranteed_unshielded_offer: None,
            fallible_unshielded_offer: Some(Sp::new(offer)),
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: PedersenRandomness::from(0),
        };
        let base = base_with_intents(vec![(1, intent)]);
        let deficits = ledger_unshielded_deficits(&Transaction::Standard(base)).unwrap();
        assert_eq!(deficits, vec![(custom, 42, 1)]);
    }

    /// An offer that already spends some shielded coins but is still short appears as a negative
    /// shielded cell in ledger `balance()` — the same signal an empty-input deposit uses — so
    /// `ledger_shielded_deficits` reports the remaining shortfall for top-up funding. Nullifiers the
    /// offer already spends are excluded from the wallet's remaining coin set.
    #[test]
    fn ledger_shielded_deficits_reports_remaining_shortfall_when_offer_has_inputs() {
        use midnight_storage::storage::Array;
        use midnight_zswap::{Delta, Input};
        use std::sync::Arc;
        use transient_crypto::commitment::Pedersen;
        use transient_crypto::curve::Fr;
        use transient_crypto::merkle_tree::MerkleTreeDigest;
        use transient_crypto::proofs::Proof;

        let token = ShieldedTokenType(HashOutput([0x42; 32]));
        let spent_nul = Nullifier(HashOutput([0xAA; 32]));

        // Deltas-only shape: an input nullifier is present so the offer
        // is not "outputs and no inputs", yet the delta still shows a 60-unit shortfall.
        let offer = ZswapOffer {
            inputs: vec![Input {
                nullifier: spent_nul,
                value_commitment: Pedersen::from(PedersenRandomness::from(0)),
                contract_address: None,
                merkle_tree_root: MerkleTreeDigest::from(Fr::from(0u64)),
                proof: Arc::new(Proof(vec![])),
            }]
            .into(),
            outputs: Array::new(),
            transient: Array::new(),
            deltas: vec![Delta {
                token_type: token,
                value: -60,
            }]
            .into(),
        };
        let mut base = base_with_intents(vec![]);
        base.guaranteed_coins = Some(Sp::new(offer));

        let deficits = ledger_shielded_deficits(&Transaction::Standard(base.clone())).unwrap();
        assert_eq!(
            deficits,
            vec![(token, 60, 0)],
            "remaining shortfall must be funded even when the offer already has inputs"
        );

        let already = spent_shielded_nullifiers(&base);
        assert!(already.contains(&spent_nul));
        // A wallet coin whose nullifier the offer already spent must not be selected for the top-up.
        let wallet_coins = [
            (spent_nul, qci(token, 100)),
            (Nullifier(HashOutput([0xBB; 32])), qci(token, 60)),
        ];
        let remaining: Vec<_> = wallet_coins
            .into_iter()
            .filter(|(nul, _)| !already.contains(nul))
            .map(|(_, c)| c)
            .collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].value, 60);
        let plan = plan_shielded_inputs(&remaining, &[(token, 60)]).unwrap();
        assert_eq!(plan.coins.len(), 1);
        assert_eq!(plan.coins[0].value, 60);
    }

    /// A balancing offer with no inputs and no outputs carries nothing in the guaranteed section, so the
    /// assembled intent drops it to None rather than emitting a degenerate 0-in/0-out offer — the shape a
    /// fee-less transfer takes once its NIGHT movement rides the fallible offer.
    #[test]
    fn assemble_proven_intent_drops_an_empty_guaranteed_offer_to_none() {
        let empty: UnshieldedOffer<MnSig, InMemoryDB> = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![].into(),
            signatures: vec![].into(),
        };
        let intent = assemble_proven_intent(
            &empty,
            None,
            &empty_intent_skeleton(),
            None,
            Timestamp::from_secs(0),
        );
        assert!(
            intent.guaranteed_unshielded_offer.is_none(),
            "an empty balancing offer must not become a guaranteed offer"
        );
    }

    /// Consolidating several of the wallet's own NIGHT coins into one self-output is balance-neutral:
    /// attached to a fresh fallible segment, that segment nets to zero per the ledger's own balance().
    #[test]
    fn fallible_consolidation_offer_nets_the_segment_to_zero() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        let coins = vec![
            night_pool_utxo(&vk_hex, 100, 1, 0),
            night_pool_utxo(&vk_hex, 250, 2, 0),
        ];
        let mut claimed = Vec::new();
        let offer =
            build_fallible_consolidation_offer(&coins, &mut claimed, &vk, "sender").unwrap();

        // Both coins are spent and folded into a single change output of their full value.
        assert_eq!(offer.inputs.iter_deref().count(), 2);
        let out_total: u128 = offer.outputs.iter_deref().map(|o| o.value).sum();
        assert_eq!(out_total, 350);
        assert_eq!(claimed.len(), 2);

        // On a fresh fallible segment, the ledger sees the segment as balanced.
        let mut intent = empty_intent_skeleton();
        intent.fallible_unshielded_offer = Some(Sp::new(offer));
        let base = base_with_intents(vec![(3, intent)]);
        let imbalances = tx_balance_imbalances(&Transaction::Standard(base)).unwrap();
        assert!(
            imbalances.is_empty(),
            "consolidation must net to zero: {imbalances:?}"
        );
    }

    /// Funding a fallible unshielded offer in its own segment nets that segment to zero — the core Gap B
    /// invariant, checked via the ledger's own `balance()`.
    #[test]
    fn fallible_balancing_nets_the_segment_to_zero() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        // A dapp fallible offer at segment 2: a 100-NIGHT output, no inputs (the deficit).
        let dapp_out = UtxoOutput {
            value: 100,
            owner: UserAddress::from(vk.clone()),
            type_: NIGHT,
        };
        let dapp_fallible = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![dapp_out.clone()].into(),
            signatures: vec![].into(),
        };
        let mut intent = intent_with(None, None);
        intent.fallible_unshielded_offer = Some(Sp::new(dapp_fallible));
        let base = base_with_intents(vec![(2, intent)]);

        // Before balancing, segment 2 is overspent by the 100-NIGHT output.
        assert!(!tx_balance_imbalances(&Transaction::Standard(base.clone()))
            .unwrap()
            .is_empty());

        // Build the wallet's fallible balancing offer (a 100-coin covers the 100 deficit; the dapp's
        // output is re-emitted), attach it to segment 2, and confirm the segment nets to zero.
        let pool = vec![night_pool_utxo(&vk_hex, 100, 1, 0)];
        let mut claimed = Vec::new();
        let (foffer, _) = build_night_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            100,
            vec![dapp_out],
            None,
        )
        .unwrap();
        let mut balanced = base;
        attach_fallible_offer(&mut balanced, 2, &foffer);

        let imbalances = tx_balance_imbalances(&Transaction::Standard(balanced)).unwrap();
        assert!(
            imbalances.is_empty(),
            "fallible segment must be balanced: {imbalances:?}"
        );
    }

    /// A sender-owned UTXO of an arbitrary unshielded token, for pools that are not NIGHT.
    fn token_pool_utxo(
        vk_hex: &str,
        token: UnshieldedTokenType,
        value: u128,
        ih_byte: u8,
    ) -> UnshieldedUtxo {
        UnshieldedUtxo {
            token_type: hex::encode(token.0 .0),
            value,
            intent_hash: hex::encode([ih_byte; 32]),
            output_index: 0,
            owner: vk_hex.to_string(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        }
    }

    /// The unshielded counterpart of `fallible_balancing_nets_the_segment_to_zero`: a deficit in a
    /// **custom** unshielded token must be funded from the wallet's coins of that token, exactly as a
    /// NIGHT deficit is. Nothing about the ledger's balance check is NIGHT-specific — `balance()`
    /// keys on `TokenType::Unshielded(t)` for every `t`.
    #[test]
    fn fallible_balancing_nets_a_custom_unshielded_token_to_zero() {
        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();
        let token = UnshieldedTokenType(HashOutput([0x5a; 32]));

        // A dapp fallible offer at segment 2: a 100-unit output of `token`, no inputs (the deficit).
        let dapp_out = UtxoOutput {
            value: 100,
            owner: UserAddress::from(vk.clone()),
            type_: token,
        };
        let dapp_fallible = UnshieldedOffer {
            inputs: vec![].into(),
            outputs: vec![dapp_out.clone()].into(),
            signatures: vec![].into(),
        };
        let mut intent = intent_with(None, None);
        intent.fallible_unshielded_offer = Some(Sp::new(dapp_fallible));
        let base = base_with_intents(vec![(2, intent)]);

        // Before balancing, segment 2 is overspent by the 100-unit output.
        assert!(!tx_balance_imbalances(&Transaction::Standard(base.clone()))
            .unwrap()
            .is_empty());

        // The wallet holds exactly the coin that covers it.
        let pool = vec![token_pool_utxo(&vk_hex, token, 100, 1)];
        let mut claimed = Vec::new();
        let (foffer, _) = build_unshielded_balancing_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            &[(token, 100)],
            vec![dapp_out],
            None,
        )
        .expect("the wallet must be able to fund a custom unshielded token deficit");
        let mut balanced = base;
        attach_fallible_offer(&mut balanced, 2, &foffer);

        let imbalances = tx_balance_imbalances(&Transaction::Standard(balanced)).unwrap();
        assert!(
            imbalances.is_empty(),
            "fallible segment must be balanced: {imbalances:?}"
        );
    }

    /// A contract call that declares it takes NIGHT in creates a real unshielded deficit: the ledger
    /// subtracts `effects.unshielded_inputs` from the segment. The balancer sizes its deficit from
    /// negative cells in `balance()` (via `ledger_unshielded_deficits`), so the contract's intake is
    /// funded even when the intent carries no unshielded offer outputs — attach the funded offer and
    /// the segment nets to zero.
    #[test]
    fn a_contract_calls_unshielded_intake_is_part_of_the_night_deficit() {
        use midnight_coin_structure::contract::ContractAddress;
        use midnight_ledger::structure::{ContractAction, ContractCall, ProofVersioned};
        use onchain_runtime::context::Effects;
        use onchain_runtime::state::EntryPointBuf;
        use onchain_runtime::transcript::Transcript;
        use transient_crypto::proofs::Proof;

        let sk: [u8; 32] = hex::decode(UNSHIELDED_SEED_HEX)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = MidnightSigningKey::from_bytes(&sk).unwrap().verifying_key();
        let vk_hex = sender_vk_hex();

        // A call whose fallible transcript declares 100 NIGHT taken IN by the contract.
        let mut effects = Effects::<InMemoryDB>::default();
        effects.unshielded_inputs = effects
            .unshielded_inputs
            .insert(LedgerTokenType::Unshielded(NIGHT), 100);
        let transcript = Sp::new(Transcript {
            gas: Default::default(),
            effects,
            program: vec![].into(),
            version: None,
        });
        let call = ContractAction::Call(Sp::new(ContractCall::<ProofMarker, InMemoryDB> {
            address: ContractAddress(HashOutput([0xC0; 32])),
            entry_point: EntryPointBuf(b"deposit".to_vec()),
            guaranteed_transcript: None,
            fallible_transcript: Some(transcript),
            communication_commitment: Default::default(),
            proof: ProofVersioned::V2(Proof(vec![])),
        }));

        let mut intent = intent_with(None, None);
        intent.actions = vec![call].into();
        let base = base_with_intents(vec![(2, intent)]);

        // The ledger sees segment 2 short by the 100 NIGHT the contract takes in.
        let imbalances = tx_balance_imbalances(&Transaction::Standard(base.clone())).unwrap();
        assert!(
            !imbalances.is_empty(),
            "the contract's declared intake must show as a deficit"
        );

        let deficits = ledger_unshielded_deficits(&Transaction::Standard(base.clone())).unwrap();
        assert_eq!(
            deficits,
            vec![(NIGHT, 100, 2)],
            "the balancer must fund the contract's declared intake, not just the offer outputs"
        );

        // No fallible offer outputs to re-emit — fund from the deficit alone and attach.
        let pool = vec![night_pool_utxo(&vk_hex, 100, 1, 0)];
        let mut claimed = Vec::new();
        let (foffer, _) = build_unshielded_balancing_offer(
            &pool,
            &mut claimed,
            &vk,
            "sender",
            &[(NIGHT, 100)],
            vec![],
            None,
        )
        .expect("wallet must fund a contract-only unshielded intake");
        let mut balanced = base;
        attach_fallible_offer(&mut balanced, 2, &foffer);

        let imbalances = tx_balance_imbalances(&Transaction::Standard(balanced)).unwrap();
        assert!(
            imbalances.is_empty(),
            "funding the contract intake must net the segment to zero: {imbalances:?}"
        );
    }

    /// A proven tx whose single intent carries both a guaranteed and a fallible wallet input, at a
    /// non-zero segment — the shape the signer must sign across both offers.
    fn build_proven_tx_with_fallible(vk: &VerifyingKey) -> Vec<u8> {
        let night_offer = |value: u128, ih: u8| UnshieldedOffer {
            inputs: vec![UtxoSpend {
                value,
                owner: vk.clone(),
                type_: NIGHT,
                intent_hash: IntentHash(HashOutput([ih; 32])),
                output_no: 0,
            }]
            .into(),
            outputs: vec![UtxoOutput {
                value,
                owner: UserAddress::from(vk.clone()),
                type_: NIGHT,
            }]
            .into(),
            signatures: vec![].into(),
        };
        let intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(night_offer(1_000_000, 7))),
            fallible_unshielded_offer: Some(Sp::new(night_offer(500_000, 8))),
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let intents: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1, intent);
        let stx = StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents,
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        };
        let tx: TxProven = Transaction::Standard(stx);
        let mut out = Vec::new();
        tagged_serialize(&tx, &mut out).unwrap();
        out
    }

    /// Sign + seal a tx with both a guaranteed and a fallible wallet input: the sealed tx carries a
    /// signature on *each* offer (the ledger's `Intent::sign` signs both).
    #[test]
    fn sign_and_seal_covers_the_fallible_offer_inputs() {
        let signer = MidnightSigner::mainnet();
        let key = packed_signing_key(UNSHIELDED_SEED_HEX);
        let vk = MidnightSigningKey::from_bytes(&hex::decode(UNSHIELDED_SEED_HEX).unwrap())
            .unwrap()
            .verifying_key();
        let tx_bytes = build_proven_tx_with_fallible(&vk);

        // Two signatures: one guaranteed input, one fallible input.
        let out = signer.sign_transaction(key.expose(), &tx_bytes).unwrap();
        let mut r: &[u8] = &out.signature[..];
        let _a = MnSig::deserialize(&mut r, 0).unwrap();
        let _b = MnSig::deserialize(&mut r, 0).unwrap();
        assert!(r.is_empty(), "expected exactly two signatures");

        // Seal: each offer carries its own input's signature.
        let sealed_bytes = signer.encode_signed_transaction(&tx_bytes, &out).unwrap();
        let mut sr: &[u8] = sealed_bytes.as_slice();
        let sealed: Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB> =
            tagged_deserialize(&mut sr).unwrap();
        let Transaction::Standard(sealed_stx) = sealed else {
            panic!("standard");
        };
        let pair = sealed_stx.intents.iter().next().unwrap();
        let (_seg, intent_sp) = pair.deref();
        let intent = intent_sp.deref();
        let g_sigs = intent
            .guaranteed_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        let f_sigs = intent
            .fallible_unshielded_offer
            .as_ref()
            .map(|o| o.deref().signatures.len())
            .unwrap_or(0);
        assert_eq!(g_sigs, 1, "guaranteed input must be signed");
        assert_eq!(f_sigs, 1, "fallible input must be signed");
    }

    #[test]
    fn tx_network_id_must_match_chain() {
        // Exact and case-insensitive matches pass; a custom feature testnet matches its reference.
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "preview").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "Preview").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:mainnet", "mainnet").is_ok());
        assert!(ensure_tx_network_id_matches_chain("midnight:feature-x", "feature-x").is_ok());

        // Mismatches are rejected — never balance a mainnet tx while pointed at a testnet, or a
        // tx built for one custom net while signing for another.
        assert!(ensure_tx_network_id_matches_chain("midnight:preview", "mainnet").is_err());
        assert!(ensure_tx_network_id_matches_chain("midnight:mainnet", "preview").is_err());
        assert!(ensure_tx_network_id_matches_chain("midnight:feature-x", "preview").is_err());
    }

    // --- plan_segment_effects: the wallet-relative effects, per segment, the policy seam gates on ---

    fn addrs() -> MidnightAddresses {
        MidnightAddresses {
            unshielded: "mn_addr_unshielded".into(),
            shielded: "mn_shield_addr".into(),
            dust: "mn_dust_addr".into(),
        }
    }

    fn vk_of(seed_hex: &str) -> VerifyingKey {
        MidnightSigningKey::from_bytes(&hex::decode(seed_hex).unwrap())
            .unwrap()
            .verifying_key()
    }

    fn night_input(value: u128, owner: VerifyingKey) -> UtxoSpend {
        UtxoSpend {
            value,
            owner,
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([9u8; 32])),
            output_no: 0,
        }
    }

    fn night_output(value: u128, owner: UserAddress) -> UtxoOutput {
        UtxoOutput {
            value,
            owner,
            type_: NIGHT,
        }
    }

    fn offer(
        inputs: Vec<UtxoSpend>,
        outputs: Vec<UtxoOutput>,
    ) -> UnshieldedOffer<MnSig, InMemoryDB> {
        UnshieldedOffer {
            inputs: inputs.into(),
            outputs: outputs.into(),
            signatures: vec![].into(),
        }
    }

    /// Unshielded balancing on the guaranteed segment: the wallet's input is outflow, its own change is
    /// inflow, the dapp's output is excluded — so segment 0 nets exactly the NIGHT the wallet funded.
    #[test]
    fn plan_segment_effects_unshielded_nets_input_minus_wallet_outputs() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let dapp_ua = UserAddress::from(vk_of(OTHER_SEED_HEX));
        let offer = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![
                night_output(300_000, wallet_ua), // wallet change
                night_output(700_000, dapp_ua),   // dapp recipient — excluded
            ],
        );
        let segs = plan_segment_effects(&addrs(), &wallet_ua, &[(0, &offer)], &[], &[], 0).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(segs[0].effects.len(), 1);
        assert_eq!(segs[0].effects[0].address, "mn_addr_unshielded");
        assert_eq!(
            segs[0].effects[0].diff,
            vec![(
                TokenType::Native.to_wire_token_type(),
                "-700000".to_string()
            )]
        );
    }

    /// An amount past `i128::MAX` fails the effects rather than wrapping: `u128::MAX as i128` is `-1`,
    /// so the outflow would have read as an inflow of 1. `i128::MAX` itself still fits, and two of them
    /// summed in one token overflow the net, which fails too.
    #[test]
    fn plan_segment_effects_refuses_amounts_outside_i128() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let fits = i128::MAX as u128;

        let at_max = offer(vec![night_input(fits, wallet.clone())], vec![]);
        let segs =
            plan_segment_effects(&addrs(), &wallet_ua, &[(0, &at_max)], &[], &[], 0).unwrap();
        assert_eq!(segs[0].effects[0].diff[0].1, format!("-{fits}"));

        for value in [fits + 1, u128::MAX] {
            let wrapped = offer(vec![night_input(value, wallet.clone())], vec![]);
            assert!(
                plan_segment_effects(&addrs(), &wallet_ua, &[(0, &wrapped)], &[], &[], 0).is_err(),
                "{value}"
            );
        }

        let twice = offer(
            vec![night_input(fits, wallet.clone()), night_input(fits, wallet)],
            vec![],
        );
        assert!(plan_segment_effects(&addrs(), &wallet_ua, &[(0, &twice)], &[], &[], 0).is_err());
    }

    #[test]
    fn signed_amount_and_net_add_stay_inside_i128() {
        assert_eq!(signed_amount(i128::MAX as u128).unwrap(), i128::MAX);
        assert!(signed_amount(i128::MAX as u128 + 1).is_err());
        assert!(signed_amount(u128::MAX).is_err());

        let mut net = -i128::MAX;
        net_add(&mut net, -1).unwrap();
        assert_eq!(net, i128::MIN);
        assert!(net_add(&mut net, -1).is_err());
        assert_eq!(net, i128::MIN, "a failed add leaves the net as it was");
    }

    /// The guaranteed offer (segment 0) and a fallible offer (segment 1) fund NIGHT independently, so
    /// each lands in its own segment — the distinction the policy needs.
    #[test]
    fn plan_segment_effects_splits_guaranteed_and_fallible_offers() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let guaranteed = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![night_output(400_000, wallet_ua)],
        );
        let fallible = offer(vec![night_input(200_000, wallet.clone())], vec![]);
        let segs = plan_segment_effects(
            &addrs(),
            &wallet_ua,
            &[(0, &guaranteed), (1, &fallible)],
            &[],
            &[],
            0,
        )
        .unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(
            segs[0].effects[0].diff,
            vec![(
                TokenType::Native.to_wire_token_type(),
                "-600000".to_string()
            )]
        );
        assert_eq!(segs[1].segment, 1);
        assert_eq!(
            segs[1].effects[0].diff,
            vec![(
                TokenType::Native.to_wire_token_type(),
                "-200000".to_string()
            )]
        );
    }

    /// A dapp paying out NIGHT and a custom token from the guaranteed section, planned the way the
    /// balancer plans it: the deficits come from the ledger's balance, the wallet's offer re-emits the
    /// dapp's outputs and funds both tokens. The effects show each token's outflow on its own, the
    /// custom token included, with the dapp's outputs and the wallet's change netted out.
    #[test]
    fn plan_segment_effects_counts_a_funded_custom_token_as_its_own_outflow() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let dapp_ua = UserAddress::from(vk_of(OTHER_SEED_HEX));
        let custom = UnshieldedTokenType(HashOutput([0xab; 32]));
        let payout = offer(
            vec![],
            vec![
                night_output(500, dapp_ua),
                UtxoOutput {
                    value: 60,
                    owner: dapp_ua,
                    type_: custom,
                },
            ],
        );
        let base = base_with_intents(vec![(1, intent_with(Some(payout), None))]);

        let deficits: Vec<(UnshieldedTokenType, u128)> =
            ledger_unshielded_deficits(&Transaction::Standard(base.clone()))
                .unwrap()
                .into_iter()
                .map(|(token, need, segment)| {
                    assert_eq!(segment, 0, "a guaranteed payout is a segment-0 deficit");
                    (token, need)
                })
                .collect();
        let chosen = base.intents.get(&1).map(|intent| (1, (*intent).clone()));
        let (_, _, outputs_in) = balancing_intent(&base, chosen, false, false).unwrap();

        let vk_hex = sender_vk_hex();
        let mut custom_utxo = night_pool_utxo(&vk_hex, 100, 1, 0);
        custom_utxo.token_type = unshielded_token_wire(custom);
        let pool = vec![custom_utxo, night_pool_utxo(&vk_hex, 1_000_000, 2, 0)];
        let (funding, _) = build_unshielded_balancing_offer(
            &pool,
            &mut Vec::new(),
            &wallet,
            "sender",
            &deficits,
            outputs_in,
            None,
        )
        .unwrap();

        let segs =
            plan_segment_effects(&addrs(), &wallet_ua, &[(0, &funding)], &[], &[], 0).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(segs[0].effects.len(), 1);
        assert_eq!(segs[0].effects[0].address, "mn_addr_unshielded");
        assert_eq!(
            segs[0].effects[0].diff,
            vec![
                (TokenType::Native.to_wire_token_type(), "-500".to_string()),
                (unshielded_token_wire(custom), "-60".to_string()),
            ]
        );
    }

    /// A contract call that takes NIGHT in, planned the way the balancer plans it: the ledger reports
    /// the intake as a deficit in the call's fallible segment, and the wallet funds it there with change.
    /// The effects show the intake as the wallet's outflow in that segment, net of the change, though
    /// the transaction carries no output paying anyone.
    #[test]
    fn plan_segment_effects_counts_a_contracts_unshielded_intake_as_outflow() {
        use midnight_coin_structure::contract::ContractAddress;
        use midnight_ledger::structure::{ContractAction, ContractCall, ProofVersioned};
        use onchain_runtime::context::Effects;
        use onchain_runtime::state::EntryPointBuf;
        use onchain_runtime::transcript::Transcript;

        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());

        let mut effects = Effects::<InMemoryDB>::default();
        effects.unshielded_inputs = effects
            .unshielded_inputs
            .insert(LedgerTokenType::Unshielded(NIGHT), 100);
        let call = ContractAction::Call(Sp::new(ContractCall::<ProofMarker, InMemoryDB> {
            address: ContractAddress(HashOutput([0xC0; 32])),
            entry_point: EntryPointBuf(b"deposit".to_vec()),
            guaranteed_transcript: None,
            fallible_transcript: Some(Sp::new(Transcript {
                gas: Default::default(),
                effects,
                program: vec![].into(),
                version: None,
            })),
            communication_commitment: Default::default(),
            proof: ProofVersioned::V2(ZswapProof(vec![])),
        }));
        let mut intent = intent_with(None, None);
        intent.actions = vec![call].into();
        let base = base_with_intents(vec![(2, intent.clone())]);

        assert_eq!(
            ledger_unshielded_deficits(&Transaction::Standard(base)).unwrap(),
            vec![(NIGHT, 100, 2)]
        );
        let pool = vec![night_pool_utxo(&sender_vk_hex(), 150, 1, 0)];
        let (funding, _) = build_unshielded_balancing_offer(
            &pool,
            &mut Vec::new(),
            &wallet,
            "sender",
            &[(NIGHT, 100)],
            fallible_outputs_of(&intent),
            None,
        )
        .unwrap();

        let segs =
            plan_segment_effects(&addrs(), &wallet_ua, &[(2, &funding)], &[], &[], 0).unwrap();
        assert_eq!(segs.len(), 1, "nothing moves in the guaranteed segment");
        assert_eq!(segs[0].segment, 2);
        assert_eq!(
            segs[0].effects,
            vec![TransactionEffect {
                address: "mn_addr_unshielded".to_string(),
                diff: vec![(TokenType::Native.to_wire_token_type(), "-100".to_string())],
            }]
        );
    }

    /// Shielded funding nets spent coins against minted self-change, per token, in the plan's segment.
    #[test]
    fn plan_segment_effects_shielded_nets_spend_minus_change() {
        let token = ShieldedTokenType(HashOutput([7u8; 32]));
        let plans = vec![ShieldedSpendPlan {
            segment: 0,
            coins: vec![qci(token, 100), qci(token, 40)],
            change: vec![(token, 20)],
        }];
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let segs = plan_segment_effects(
            &addrs(),
            &wallet_ua,
            &[(0, &offer(vec![], vec![]))],
            &plans,
            &[],
            0,
        )
        .unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(segs[0].effects[0].address, "mn_shield_addr");
        assert_eq!(
            segs[0].effects[0].diff,
            vec![(hex::encode(token.into_inner().0), "-120".to_string())]
        );
    }

    /// A shielded receipt the dapp routes to the wallet nets against the wallet's own spend in the same
    /// segment, so the shielded effect is the wallet's true movement rather than its outflow bound: a
    /// 100 spend with 20 self-change and a 50 dapp-routed receipt nets to -30.
    #[test]
    fn plan_segment_effects_shielded_inflow_nets_against_spend() {
        let token = ShieldedTokenType(HashOutput([9u8; 32]));
        let plans = vec![ShieldedSpendPlan {
            segment: 0,
            coins: vec![qci(token, 100)],
            change: vec![(token, 20)],
        }];
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let segs = plan_segment_effects(
            &addrs(),
            &wallet_ua,
            &[(0, &offer(vec![], vec![]))],
            &plans,
            &[(0, token, 50)],
            0,
        )
        .unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(segs[0].effects[0].address, "mn_shield_addr");
        // -100 + 20 + 50 = -30
        assert_eq!(
            segs[0].effects[0].diff,
            vec![(hex::encode(token.into_inner().0), "-30".to_string())]
        );
    }

    /// A dapp-routed receipt with no matching wallet spend surfaces as positive shielded movement in its
    /// offer's segment — the dapp paying value into the wallet with no wallet outflow.
    #[test]
    fn plan_segment_effects_shielded_inflow_only_is_positive() {
        let token = ShieldedTokenType(HashOutput([3u8; 32]));
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let segs = plan_segment_effects(
            &addrs(),
            &wallet_ua,
            &[(0, &offer(vec![], vec![]))],
            &[],
            &[(1, token, 250)],
            0,
        )
        .unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 1);
        assert_eq!(
            segs[0].effects[0].diff,
            vec![(hex::encode(token.into_inner().0), "250".to_string())]
        );
    }

    /// Hermetic end-to-end of the shielded-inflow WIRING: `scan_shielded_inflow` trial-decrypts the
    /// incoming Zswap offers with the wallet's keys and keys each recognized receipt by its offer's
    /// segment — the guaranteed offer into segment 0, a fallible offer into its own segment — while a
    /// foreign-keyed output in the same offer is ignored. No prover, no indexer: outputs are built as
    /// proof-preimage (recognition reads only ciphertext + commitment), and the crypto provider's
    /// shielded seed is `packed_signing_key`'s filler (0x11), so a locally-built key of the same seed
    /// addresses outputs it recognizes.
    #[test]
    fn scan_shielded_inflow_recognizes_wallet_receipts_by_segment() {
        use midnight_coin_structure::coin::Info as CoinInfo;
        use midnight_zswap::keys::{SecretKeys as ZswapSecretKeys, Seed as ZswapSeed};
        use midnight_zswap::Output as ZswapOutput;
        use rand::rngs::OsRng;
        use rand::Rng as _;

        let crypto_provider = MidnightSigner::mainnet()
            .crypto_provider(&packed_signing_key(UNSHIELDED_SEED_HEX))
            .unwrap();
        let wallet_keys = ZswapSecretKeys::from(ZswapSeed::from([0x11u8; 32]));
        let foreign_keys = ZswapSecretKeys::from(ZswapSeed::from([0x99u8; 32]));

        let mut rng = OsRng;
        let token = ShieldedTokenType(HashOutput([6u8; 32]));
        let output_to = |keys: &ZswapSecretKeys, value: u128, seg: u16, rng: &mut OsRng| {
            let coin = CoinInfo {
                nonce: rng.r#gen(),
                type_: token,
                value,
            };
            ZswapOutput::new(
                rng,
                &coin,
                Some(seg),
                &keys.coin_public_key(),
                Some(keys.enc_public_key()),
            )
            .unwrap()
        };

        // Guaranteed offer (segment 0): pays the wallet 5 and a foreign party 9 (which must be ignored).
        let guaranteed = ZswapOffer::new(
            vec![],
            vec![
                output_to(&wallet_keys, 5, 0, &mut rng),
                output_to(&foreign_keys, 9, 0, &mut rng),
            ],
            vec![],
        )
        .unwrap();
        // A fallible offer at segment 1 pays the wallet 7.
        let fallible_offer = ZswapOffer::new(
            vec![],
            vec![output_to(&wallet_keys, 7, 1, &mut rng)],
            vec![],
        )
        .unwrap();
        let fallible: MnHashMap<u16, _, InMemoryDB> = MnHashMap::new().insert(1, fallible_offer);

        let mut inflow = scan_shielded_inflow(Some(&guaranteed), &fallible, &crypto_provider);
        inflow.sort();
        assert_eq!(
            inflow,
            vec![(0, token, 5), (1, token, 7)],
            "wallet receipts keyed by segment; the foreign-keyed output is ignored"
        );
    }

    /// The DUST fee is a guaranteed cost, so it shows up as a negative `dust` movement in segment 0 even
    /// with no other movement anywhere.
    #[test]
    fn plan_segment_effects_dust_outflow_is_guaranteed_in_segment_0() {
        let wallet_ua = UserAddress::from(vk_of(UNSHIELDED_SEED_HEX));
        let segs = plan_segment_effects(
            &addrs(),
            &wallet_ua,
            &[(0, &offer(vec![], vec![]))],
            &[],
            &[],
            50_000,
        )
        .unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment, 0);
        assert_eq!(segs[0].effects[0].address, "mn_dust_addr");
        assert_eq!(
            segs[0].effects[0].diff,
            vec![("dust".to_string(), "-50000".to_string())]
        );
    }

    /// All three domains, with a token spent in two segments: each segment keeps its own movement, and
    /// the guaranteed segment also carries the dust fee.
    #[test]
    fn plan_segment_effects_groups_domains_across_segments() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let token = ShieldedTokenType(HashOutput([5u8; 32]));
        let offer = offer(
            vec![night_input(2_000_000, wallet.clone())],
            vec![night_output(500_000, wallet_ua)],
        );
        let plans = vec![
            ShieldedSpendPlan {
                segment: 0,
                coins: vec![qci(token, 100)],
                change: vec![(token, 30)],
            },
            ShieldedSpendPlan {
                segment: 1,
                coins: vec![qci(token, 50)],
                change: vec![],
            },
        ];
        let segs = plan_segment_effects(&addrs(), &wallet_ua, &[(0, &offer)], &plans, &[], 12_345)
            .unwrap();
        assert_eq!(segs.len(), 2);

        // segment 0: night (-1_500_000), shielded (-70), dust (-12_345)
        let seg0 = &segs[0];
        assert_eq!(seg0.segment, 0);
        let night = seg0
            .effects
            .iter()
            .find(|e| e.address == "mn_addr_unshielded")
            .unwrap();
        assert_eq!(
            night.diff,
            vec![(
                TokenType::Native.to_wire_token_type(),
                "-1500000".to_string()
            )]
        );
        let shielded = seg0
            .effects
            .iter()
            .find(|e| e.address == "mn_shield_addr")
            .unwrap();
        // -100 + 30 = -70
        assert_eq!(
            shielded.diff,
            vec![(hex::encode(token.into_inner().0), "-70".to_string())]
        );
        let dust = seg0
            .effects
            .iter()
            .find(|e| e.address == "mn_dust_addr")
            .unwrap();
        assert_eq!(dust.diff, vec![("dust".to_string(), "-12345".to_string())]);

        // segment 1: shielded only (-50)
        let seg1 = &segs[1];
        assert_eq!(seg1.segment, 1);
        assert_eq!(seg1.effects.len(), 1);
        assert_eq!(seg1.effects[0].address, "mn_shield_addr");
        assert_eq!(
            seg1.effects[0].diff,
            vec![(hex::encode(token.into_inner().0), "-50".to_string())]
        );
    }

    /// A segment whose only movement nets to zero (input fully returned as change) yields no entry.
    #[test]
    fn plan_segment_effects_omits_zero_net_segments() {
        let wallet = vk_of(UNSHIELDED_SEED_HEX);
        let wallet_ua = UserAddress::from(wallet.clone());
        let offer = offer(
            vec![night_input(1_000_000, wallet.clone())],
            vec![night_output(1_000_000, wallet_ua)],
        );
        assert!(
            plan_segment_effects(&addrs(), &wallet_ua, &[(0, &offer)], &[], &[], 0)
                .unwrap()
                .is_empty()
        );
    }
}
