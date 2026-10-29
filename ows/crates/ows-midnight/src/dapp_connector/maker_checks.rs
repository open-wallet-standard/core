//! What a taker checks on a sealed maker offer before it builds or proves anything for it. MIP-0005
//! leaves it to the receiver: decoding an offer establishes only that its bytes are a transaction, so a
//! receiver confirms that the offer has not expired, that its proofs and signatures verify, and that
//! the coins backing it are still unspent.
//!
//! Some of that rests on chain state a taker does not hold, and is left to the node, which rejects the
//! merged transaction whole:
//! - a contract call's proof verifies against the contract's verifier key, which lives in the
//!   contract's on-chain state;
//! - a DUST spend's proof commits to the DUST commitment and generation tree roots at its `ctime`,
//!   which the indexer does not expose;
//! - a shielded input is live while its nullifier is unspent and the Merkle root its proof commits to
//!   is inside the node's recency window, and the indexer offers no lookup of either.

use std::collections::BTreeMap;
use std::ops::Deref as _;
use std::path::Path;

use midnight_base_crypto::signatures::{Signature as MnSig, VerifyingKey};
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::UserAddress;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger::dust::DustParameters;
use midnight_ledger::error::MalformedTransaction;
use midnight_ledger::structure::{
    ErasedIntent, LedgerParameters, LedgerState, ProofMarker, StandardTransaction, Transaction,
    UtxoSpend,
};
use midnight_ledger::verify::{StateReference, WellFormedStrictness};
use midnight_serialize::tagged_deserialize;
use midnight_storage::arena::{ArenaHash, Sp};
use midnight_storage::db::{InMemoryDB, DB};
use onchain_runtime::state::{ContractMaintenanceAuthority, ContractOperation, EntryPointBuf};
use ows_signer::chains::MidnightSigner;
use transient_crypto::commitment::PureGeneratorPedersen;
use transient_crypto::merkle_tree::MerkleTreeDigest;

use super::build::{encode_unshielded_address, err};

type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;
type StdSealed = StandardTransaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// How close to its expiry a maker offer may be and still be taken. The taker has yet to prove its half
/// and land the merged transaction, which the ledger rejects once its block is past the maker's TTL, so
/// an offer expiring sooner would be proved for nothing.
const EXPIRY_MARGIN_SECS: u64 = 60;

/// Check a sealed maker offer against the chain before the taker plans its half: that it does not
/// expire within [`EXPIRY_MARGIN_SECS`] of the chain tip, that its proofs and signatures verify, and
/// that the indexer still lists every unshielded coin it spends as unspent. The indexer is the one the
/// caller's vault names, and the maker's coin set is cached under that vault.
pub(super) fn check_maker(
    chain_id: &str,
    maker_bytes: &[u8],
    vault_path: Option<&Path>,
) -> Result<(), std::io::Error> {
    let mut r: &[u8] = maker_bytes;
    let maker: TxSealed = tagged_deserialize(&mut r)
        .map_err(|e| err(format!("failed to parse sealed maker tx: {e}")))?;
    let Transaction::Standard(base) = &maker else {
        return Err(err(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    let indexer_url = crate::wallet::resolve_indexer_url(chain_id, vault_path)?;
    let (params, tip_secs) =
        crate::block_on(crate::ledger_params::fetch_indexer_tip(&indexer_url))?;
    let tip = Timestamp::from_secs(tip_secs);
    ensure_not_expiring(base, tip)?;
    ensure_verifies(&maker, &params, tip)?;
    let scope = crate::wallet::signing_scope(chain_id, vault_path);
    ensure_inputs_unspent(chain_id, base, |address| {
        crate::block_on(crate::get_unshielded_utxos_for_display(
            &indexer_url,
            address,
            &scope,
        ))
    })
}

/// When the maker offer stops being takeable: the earliest TTL among its intents, since the ledger
/// checks each intent's TTL against the block it lands in. An offer with no intent carries no TTL.
fn maker_expiry(maker: &StdSealed) -> Option<Timestamp> {
    maker
        .intents
        .iter()
        .map(|pair| pair.deref().1.deref().ttl)
        .min()
}

/// Refuse a maker offer that expires before a merged transaction built now could land.
fn ensure_not_expiring(maker: &StdSealed, tip: Timestamp) -> Result<(), std::io::Error> {
    let Some(expiry) = maker_expiry(maker) else {
        return Ok(());
    };
    let expiry = expiry.to_secs();
    let tip = tip.to_secs();
    if expiry <= tip.saturating_add(EXPIRY_MARGIN_SECS) {
        let state = if expiry < tip {
            "expired"
        } else {
            "about to expire"
        };
        return Err(err(format!(
            "refusing a maker offer that is {state}: it expires at {expiry}, and the chain tip is at \
             {tip}, so the merged transaction could not land before it (at least {EXPIRY_MARGIN_SECS}s \
             must remain)"
        )));
    }
    Ok(())
}

/// Verify the maker offer as the node's well-formedness check does, short of what needs chain state:
/// its zswap proofs (against the ledger's built-in verifier keys), the signature on every unshielded
/// input and dust registration, every intent's binding, the Pedersen binding of the whole, its
/// structure, and its TTL window at `tblock`. Balancing is not enforced, since an offer is imbalanced by
/// design.
fn ensure_verifies(
    maker: &TxSealed,
    params: &LedgerParameters,
    tblock: Timestamp,
) -> Result<(), std::io::Error> {
    let Transaction::Standard(base) = maker else {
        return Err(err(
            "balanceSealedTransaction expects a Standard maker transaction",
        ));
    };
    let mut state = LedgerState::<InMemoryDB>::new(base.network_id.clone());
    state.parameters = Sp::new(params.clone());
    let mut strictness = WellFormedStrictness::default();
    strictness.enforce_balancing = false;
    strictness.verify_contract_proofs = false;
    maker
        .well_formed(&ReceiverReference(state), strictness, tblock)
        .map(|_| ())
        .map_err(|e| {
            err(format!(
                "refusing a maker offer that does not verify: {e:?}"
            ))
        })
}

/// The ledger state a receiver checks a maker offer against: the chain's parameters over an empty state.
/// A contract's operations and maintenance authority are absent, so anything that needs them is refused;
/// DUST-spend proofs are skipped, since the roots they commit to are not available to the receiver.
struct ReceiverReference(LedgerState<InMemoryDB>);

impl StateReference<InMemoryDB> for ReceiverReference {
    fn stateless_check(
        &self,
        check: impl FnOnce() -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0.stateless_check(check)
    }

    fn param_check(
        &self,
        always: bool,
        check: impl FnOnce(&LedgerParameters) -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0.param_check(always, check)
    }

    fn op_check(
        &self,
        contract: ContractAddress,
        entry_point: &EntryPointBuf,
        check: impl FnOnce(&ContractOperation) -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0.op_check(contract, entry_point, check)
    }

    fn maintenance_check(
        &self,
        contract: ContractAddress,
        check: impl FnOnce(
            &ContractMaintenanceAuthority,
        ) -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0.maintenance_check(contract, check)
    }

    fn generationless_fee_availability_check(
        &self,
        parent_intent: &ErasedIntent<InMemoryDB>,
        night_key: &VerifyingKey,
        check: impl FnOnce(u128) -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0
            .generationless_fee_availability_check(parent_intent, night_key, check)
    }

    fn dust_spend_check(
        &self,
        _ctime: Timestamp,
        _check: impl FnOnce(
            DustParameters,
            MerkleTreeDigest,
            MerkleTreeDigest,
        ) -> Result<(), MalformedTransaction<InMemoryDB>>,
    ) -> Result<(), MalformedTransaction<InMemoryDB>> {
        Ok(())
    }

    fn network_check(&self, network: &str) -> Result<(), MalformedTransaction<InMemoryDB>> {
        self.0.network_check(network)
    }

    fn ref_state_hash(&self) -> ArenaHash<<InMemoryDB as DB>::Hasher> {
        self.0.ref_state_hash()
    }
}

/// Refuse a maker offer that spends an unshielded coin the indexer no longer lists as unspent: one the
/// maker has spent since, which withdraws the offer, or one another taker's merge has already consumed.
/// `utxos_of` returns the unspent coins of an unshielded address. Matched on everything the ledger keys a
/// coin by, so a spend naming a coin with another value or token is refused too.
fn ensure_inputs_unspent(
    chain_id: &str,
    maker: &StdSealed,
    mut utxos_of: impl FnMut(&str) -> Result<Vec<crate::UnshieldedUtxo>, std::io::Error>,
) -> Result<(), std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);
    let mut by_owner: BTreeMap<String, Vec<UtxoSpend>> = BTreeMap::new();
    for pair in maker.intents.iter() {
        let intent = pair.deref().1.deref();
        let offers = [
            intent.guaranteed_unshielded_offer.as_ref(),
            intent.fallible_unshielded_offer.as_ref(),
        ];
        for offer in offers.into_iter().flatten() {
            for input in offer.inputs.iter_deref() {
                let owner =
                    encode_unshielded_address(&signer, &UserAddress::from(input.owner.clone()))?;
                by_owner.entry(owner).or_default().push(input.clone());
            }
        }
    }
    for (owner, inputs) in by_owner {
        let unspent = utxos_of(&owner)?;
        for input in inputs {
            let live = unspent.iter().any(|u| {
                crate::balance_tx::parse_intent_hash_hex(&u.intent_hash)
                    .is_ok_and(|ih| ih == input.intent_hash)
                    && u32::try_from(u.output_index).is_ok_and(|n| n == input.output_no)
                    && u.value == input.value
                    && u.token_type
                        .eq_ignore_ascii_case(&hex::encode(input.type_.0 .0))
            });
            if !live {
                return Err(err(format!(
                    "refusing a maker offer whose input {}#{} is not an unspent coin of {owner}: the \
                     maker has spent it, withdrawing the offer, or the offer was already taken",
                    hex::encode(input.intent_hash.0 .0),
                    input.output_no
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: &str = "midnight:preprod";

    /// The checked-in preprod maker: a real `makeIntent` offer, sealed, with real signatures.
    fn fixture() -> TxSealed {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap();
        let mut r: &[u8] = &bytes;
        tagged_deserialize(&mut r).unwrap()
    }

    fn standard(tx: &TxSealed) -> &StdSealed {
        match tx {
            Transaction::Standard(stx) => stx,
            Transaction::ClaimRewards(_) => panic!("not a standard transaction"),
        }
    }

    fn expiry_of(tx: &TxSealed) -> u64 {
        maker_expiry(standard(tx))
            .expect("the fixture has an intent")
            .to_secs()
    }

    #[test]
    fn an_expired_or_nearly_expired_maker_is_refused() {
        let maker = fixture();
        let expiry = expiry_of(&maker);
        let at = |tip: u64| ensure_not_expiring(standard(&maker), Timestamp::from_secs(tip));

        let e = at(expiry + 1).unwrap_err().to_string();
        assert!(e.contains("is expired"), "{e}");
        let e = at(expiry - EXPIRY_MARGIN_SECS).unwrap_err().to_string();
        assert!(e.contains("about to expire"), "{e}");
        at(expiry - EXPIRY_MARGIN_SECS - 1).unwrap();
    }

    /// The fixture verifies as the node would check it, short of chain state, within its TTL window.
    #[test]
    fn a_genuine_maker_verifies() {
        let maker = fixture();
        let tblock = Timestamp::from_secs(expiry_of(&maker) - 600);
        ensure_verifies(
            &maker,
            &midnight_ledger::structure::INITIAL_PARAMETERS,
            tblock,
        )
        .unwrap();
    }

    /// Changing what the maker signed — here, raising one of its outputs — breaks its signatures, and
    /// the taker refuses the offer before building anything for it.
    #[test]
    fn a_maker_whose_terms_changed_after_signing_is_refused() {
        let maker = fixture();
        let tblock = Timestamp::from_secs(expiry_of(&maker) - 600);
        let mut base = standard(&maker).clone();
        let (segment, mut intent) = {
            let pair = base.intents.iter().next().unwrap();
            (*pair.deref().0.deref(), pair.deref().1.deref().clone())
        };
        let mut offer = intent
            .guaranteed_unshielded_offer
            .as_deref()
            .unwrap()
            .clone();
        let mut outputs: Vec<_> = offer.outputs.iter_deref().cloned().collect();
        outputs[0].value += 1;
        offer.outputs = outputs.into();
        intent.guaranteed_unshielded_offer = Some(Sp::new(offer));
        base.intents = base.intents.insert(segment, intent);

        let e = ensure_verifies(
            &Transaction::Standard(base),
            &midnight_ledger::structure::INITIAL_PARAMETERS,
            tblock,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("does not verify"), "{e}");
    }

    /// The fixture's coins are real preprod coins, and a submission of any offer built on them spends
    /// them, so the coin set is served here rather than read from the chain.
    #[test]
    fn a_maker_whose_input_is_spent_is_refused() {
        let maker = fixture();
        let inputs: Vec<UtxoSpend> = standard(&maker)
            .intents
            .iter()
            .flat_map(|pair| {
                let intent = pair.deref().1.deref().clone();
                intent
                    .guaranteed_unshielded_offer
                    .map(|o| o.inputs.iter_deref().cloned().collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect();
        assert!(!inputs.is_empty(), "the fixture spends unshielded coins");
        let signer = MidnightSigner::from_chain_id(CHAIN);
        let owner = encode_unshielded_address(&signer, &UserAddress::from(inputs[0].owner.clone()))
            .unwrap();
        let utxo = |input: &UtxoSpend| crate::UnshieldedUtxo {
            token_type: hex::encode(input.type_.0 .0),
            value: input.value,
            intent_hash: hex::encode(input.intent_hash.0 .0),
            output_index: i64::from(input.output_no),
            owner: owner.clone(),
            ctime_unix_secs: Some(1_000),
            registered_for_dust_generation: false,
        };
        let live: Vec<_> = inputs.iter().map(utxo).collect();

        let mut asked = Vec::new();
        ensure_inputs_unspent(CHAIN, standard(&maker), |address| {
            asked.push(address.to_string());
            Ok(live.clone())
        })
        .unwrap();
        assert_eq!(asked, vec![owner.clone()]);

        let e = ensure_inputs_unspent(CHAIN, standard(&maker), |_| Ok(Vec::new()))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not an unspent coin"), "{e}");

        let mut other_value = live.clone();
        other_value[0].value += 1;
        assert!(
            ensure_inputs_unspent(CHAIN, standard(&maker), |_| Ok(other_value.clone())).is_err()
        );
    }
}
