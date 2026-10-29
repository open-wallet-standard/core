//! DApp Connector `makeTransfer`.
//!
//! `makeTransfer(desiredOutputs, options?)` asks the wallet to build a transaction that sends
//! `desiredOutputs` to their recipients. The wallet constructs the outputs (no inputs) and — since an
//! outputs-only transaction is a wallet-funded deficit — funnels it through the same
//! `plan_unsealed_proven_tx` → `authorize_proven_tx` tail as `balanceUnsealed`. The balancing is
//! planned once, before the policy seam, over mock-proven outputs; `authorize` proves the same outputs
//! for real and signs that plan, so the coins and fee the policy saw are the ones spent.

use std::path::Path;

use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_coin_structure::coin::Info as CoinInfo;
use midnight_ledger::structure::{
    Intent, ProofPreimageMarker, StandardTransaction, Transaction, UnshieldedOffer, UtxoOutput,
};
use midnight_serialize::tagged_serialize;
use midnight_storage::arena::Sp;
use midnight_storage::db::InMemoryDB;
use midnight_storage::storage::HashMap as MnHashMap;
use midnight_zswap::{Offer as ZswapOffer, Output as ZswapOutput};
use ows_signer::chains::{MidnightCryptoProvider, MidnightSigner};
use rand::rngs::OsRng;
use rand::Rng as _;
use serde::Deserialize;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::ProofPreimage;

use super::build::{
    decode_shielded_recipient, decode_unshielded_recipient, default_intent_ttl, err,
    mock_prove_unsealed, prove_preimage, wire_type_to_shielded, wire_type_to_unshielded,
    DesiredOutput, PreimageTx, TransferKind,
};

/// The intent that carries the wallet's unshielded outputs keys at a fallible segment (>= 1): the
/// ledger reserves segment 0 for the guaranteed section and rejects any intent declared there
/// (`IntentAtGuaranteedSegmentId`, surfaced by the node as `Custom error: 167`). Unshielded NIGHT
/// movement rides this segment's *fallible* offer, not the guaranteed one: only the guaranteed
/// unshielded offer's cost counts toward the guaranteed section's tight `time_to_dismiss` budget, so
/// funding a multi-UTXO NIGHT move in the guaranteed section overruns it (the node dismisses the tx).
/// Shielded Zswap outputs still ride the guaranteed section. Balancing draws the wallet's own inputs
/// into this same fallible offer.
const MAKE_TRANSFER_INTENT_SEGMENT: u16 = 1;
/// Segment 0 is the transaction's guaranteed section; a transfer's shielded outputs ride it so they
/// execute unconditionally.
const GUARANTEED_SEGMENT: u16 = 0;

/// A parsed `makeTransfer` request: the outputs to send, and whether the wallet should pay DUST fees.
#[derive(Debug, Clone)]
pub struct MakeTransferRequest {
    pub desired_outputs: Vec<DesiredOutput>,
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
struct MakeTransferJson {
    desired_outputs: Vec<DesiredOutput>,
    #[serde(default)]
    options: Option<OptionsJson>,
}

/// Parse a stringified DApp Connector `makeTransfer` request. `payFees` defaults to true.
pub fn parse_make_transfer_json(json: &str) -> Result<MakeTransferRequest, std::io::Error> {
    let req: MakeTransferJson = serde_json::from_str(json)
        .map_err(|e| std::io::Error::other(format!("invalid makeTransfer request JSON: {e}")))?;
    if req.desired_outputs.is_empty() {
        return Err(std::io::Error::other(
            "makeTransfer requires at least one desired output",
        ));
    }
    Ok(MakeTransferRequest {
        desired_outputs: req.desired_outputs,
        pay_fees: req.options.map(|o| o.pay_fees).unwrap_or(true),
    })
}

/// A `makeTransfer` planned before the policy seam: the outputs' preimage, kept so [`authorize`] proves
/// exactly these outputs, and the balancing plan built over their mock-proven form, which the seam reads
/// the effects from and [`authorize`] signs.
pub struct TransferPlan {
    preimage: PreimageTx,
    plan: crate::BalancedPlan,
}

/// Plan a `makeTransfer`: build its outputs, **mock-prove** them (proofs are fixed-size, so the fee
/// sized against them matches the real one exactly) and plan the balancing against the wallet's synced
/// coins. No real proving happens here, so a transfer denied at the seam never reaches a real proof.
pub(super) fn plan(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    req: &MakeTransferRequest,
    vault_path: Option<&Path>,
) -> Result<TransferPlan, std::io::Error> {
    let preimage = build_make_transfer_preimage(chain_id, req)?;
    // Mock-prove into the *unsealed* proven form (`mock_prove` would seal it, and the balancer only
    // consumes unsealed proven bytes).
    let mock_proven = mock_prove_unsealed(preimage.clone())?;
    let mut bytes = Vec::new();
    tagged_serialize(&mock_proven, &mut bytes)
        .map_err(|e| err(format!("serialize mock-proven makeTransfer: {e}")))?;
    let plan = crate::plan_unsealed_proven_tx(
        chain_id,
        crypto_provider,
        &bytes,
        req.pay_fees,
        vault_path,
    )?;
    Ok(TransferPlan { preimage, plan })
}

impl TransferPlan {
    /// The wallet-relative effects this transfer will have, per segment, read off the balancing plan so
    /// the **DUST fee** the transfer burns is included: a `sum(|diff|)` cap at the policy seam must see
    /// it, and request-derived effects (outputs only) would under-state it. The plan nets the wallet's
    /// inputs against its own change and outputs (the value to each recipient plus the dust fee),
    /// attributing each to the segment (guaranteed or fallible) its offer rides.
    pub(super) fn segment_effects(
        &self,
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Vec<crate::balance_tx::SegmentEffects>, std::io::Error> {
        self.plan.segment_effects(chain_id, crypto_provider)
    }

    /// The balancing plan the transfer signs, whose fee and registrations the policy seam reports.
    pub(super) fn balanced(&self) -> &crate::BalancedPlan {
        &self.plan
    }
}

/// Prove the planned outputs for real, put the proofs into the planned transaction, and sign and seal
/// it. Runs **after** the policy seam. Nothing is re-synced, re-selected or re-priced: the coins and the
/// fee are the ones the seam's effects were read from.
pub(super) fn authorize(
    chain_id: &str,
    crypto_provider: &MidnightCryptoProvider,
    transfer: TransferPlan,
    vault_path: Option<&Path>,
) -> Result<Vec<u8>, std::io::Error> {
    let TransferPlan { preimage, mut plan } = transfer;
    plan.replace_mock_proofs(prove_preimage(chain_id, preimage, vault_path)?)?;
    crate::authorize_proven_tx(chain_id, crypto_provider, plan, vault_path)
}

/// Construct the `proof-preimage` transaction for a `makeTransfer`: recipient outputs and no inputs.
/// Unshielded outputs ride the fallible unshielded offer of the maker intent (see
/// [`MAKE_TRANSFER_INTENT_SEGMENT`]); shielded outputs ride the guaranteed Zswap offer. Balancing (the
/// wallet's own inputs + change + fee) comes later.
fn build_make_transfer_preimage(
    chain_id: &str,
    req: &MakeTransferRequest,
) -> Result<PreimageTx, std::io::Error> {
    let signer = MidnightSigner::from_chain_id(chain_id);
    let (unshielded_out, shielded_out): (Vec<_>, Vec<_>) = req
        .desired_outputs
        .iter()
        .partition(|d| d.kind == TransferKind::Unshielded);

    let unshielded_offer = build_unshielded_output_offer(&signer, &unshielded_out)?;
    let zswap_offer = build_shielded_output_offer(&signer, &shielded_out)?;
    if unshielded_offer.is_none() && zswap_offer.is_none() {
        return Err(err(
            "makeTransfer produced no unshielded or shielded output",
        ));
    }

    let mut rng = OsRng;
    let intent: Intent<MnSig, ProofPreimageMarker, PedersenRandomness, InMemoryDB> = Intent {
        guaranteed_unshielded_offer: None,
        fallible_unshielded_offer: unshielded_offer.map(Sp::new),
        actions: vec![].into(),
        dust_actions: None,
        // The balancer re-aligns the TTL on the intent it owns (this one); the wallet default avoids a
        // spuriously-expired intent in the meantime.
        ttl: default_intent_ttl(),
        binding_commitment: rng.r#gen(),
    };
    let intents: MnHashMap<u16, _, InMemoryDB> =
        MnHashMap::new().insert(MAKE_TRANSFER_INTENT_SEGMENT, intent);
    let mut stx = StandardTransaction {
        network_id: signer.ledger_network_id().to_string(),
        intents,
        guaranteed_coins: zswap_offer.map(Sp::new),
        fallible_coins: MnHashMap::new(),
        binding_randomness: Default::default(),
    };
    stx.recompute_binding_randomness();
    Ok(Transaction::Standard(stx))
}

fn build_unshielded_output_offer(
    signer: &MidnightSigner,
    outputs_requested: &[&DesiredOutput],
) -> Result<Option<UnshieldedOffer<MnSig, InMemoryDB>>, std::io::Error> {
    if outputs_requested.is_empty() {
        return Ok(None);
    }
    let mut outputs = Vec::with_capacity(outputs_requested.len());
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
    outputs.sort();
    Ok(Some(UnshieldedOffer {
        inputs: vec![].into(),
        outputs: outputs.into(),
        signatures: vec![].into(),
    }))
}

fn build_shielded_output_offer(
    signer: &MidnightSigner,
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
        let out = ZswapOutput::new(&mut rng, &coin, Some(GUARANTEED_SEGMENT), &cpk, Some(epk))
            .map_err(|e| err(format!("shielded output failed: {e:?}")))?;
        outputs.push(out);
    }
    ZswapOffer::new(vec![], outputs, vec![])
        .map(Some)
        .ok_or_else(|| err("shielded Zswap offer is empty"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_outputs_and_defaults_pay_fees_true() {
        let req = parse_make_transfer_json(
            r#"{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"1000","recipient":"mn_addr_r"}]}"#,
        )
        .unwrap();
        assert_eq!(req.desired_outputs.len(), 1);
        assert_eq!(req.desired_outputs[0].value, 1000);
        assert_eq!(req.desired_outputs[0].kind, TransferKind::Unshielded);
        assert_eq!(req.desired_outputs[0].recipient, "mn_addr_r");
        assert!(req.pay_fees);
    }

    #[test]
    fn honours_pay_fees_false_and_numeric_value() {
        let req = parse_make_transfer_json(
            r#"{"desiredOutputs":[{"kind":"shielded","type":"night","value":5,"recipient":"mn_addr_r"}],"options":{"payFees":false}}"#,
        )
        .unwrap();
        assert!(!req.pay_fees);
        assert_eq!(req.desired_outputs[0].value, 5);
        assert_eq!(req.desired_outputs[0].kind, TransferKind::Shielded);
    }

    #[test]
    fn a_misspelled_option_or_a_blank_token_type_is_refused() {
        let misspelled = parse_make_transfer_json(
            r#"{"desiredOutputs":[{"kind":"unshielded","type":"night","value":5,"recipient":"mn_addr_r"}],"options":{"payfees":false}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(misspelled.contains("unknown field"), "{misspelled}");
        assert!(parse_make_transfer_json(
            r#"{"desiredOutputs":[{"kind":"unshielded","type":"","value":5,"recipient":"mn_addr_r"}]}"#,
        )
        .is_err());
    }

    #[test]
    fn rejects_empty_outputs() {
        assert!(parse_make_transfer_json(r#"{"desiredOutputs":[]}"#).is_err());
    }

    /// A valid preview unshielded address, derived so the recipient decode path is exercised for real.
    fn preview_unshielded_address() -> String {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        blob.extend_from_slice(&[0x33u8; 32]);
        MidnightSigner::preview()
            .derive_addresses(&blob)
            .expect("derive addresses")
            .unshielded
    }

    /// An outputs-only makeTransfer builds a well-formed transaction whose ledger balance shows a
    /// wallet-funded deficit — exactly the shape `plan_unsealed_proven_tx` balances.
    #[test]
    fn build_unshielded_transfer_leaves_a_deficit() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        assert_eq!(stx.network_id, "preview");
        let proven = tx.mock_prove().expect("mock prove");
        let has_deficit = proven
            .balance(None)
            .expect("balance")
            .into_iter()
            .any(|(_, bal)| bal < 0);
        assert!(
            has_deficit,
            "makeTransfer must leave a wallet-funded deficit"
        );
    }

    /// The ledger rejects an intent declared at segment 0 (the reserved guaranteed section) with
    /// `IntentAtGuaranteedSegmentId`, surfaced on-chain as `Custom error: 167`. Guard that makeTransfer
    /// keys its intent at a fallible segment (the unshielded NIGHT output rides that segment's fallible
    /// offer — see [`make_transfer_night_output_rides_the_fallible_offer`]).
    ///
    /// A full ledger `well_formed` check can't stand in here: an outputs-only transfer is imbalanced
    /// until the wallet funds it, and `well_formed` runs `pedersen_check` (the balance check) *before*
    /// the intent-segment check (verify.rs:605 vs :622), so an imbalanced tx fails on balance before the
    /// segment rule is ever reached. This structural assertion checks the segment invariant directly.
    #[test]
    fn make_transfer_intent_is_off_the_guaranteed_segment() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        assert!(
            stx.intents.get(&0).is_none(),
            "makeTransfer must not key an intent at segment 0 (IntentAtGuaranteedSegmentId / node error 167)"
        );
        assert!(
            stx.intents.get(&MAKE_TRANSFER_INTENT_SEGMENT).is_some(),
            "the maker intent rides the fallible segment"
        );
    }

    /// Unshielded NIGHT movement rides the *fallible* offer, never the guaranteed one: only the
    /// guaranteed offer loads the guaranteed section's `time_to_dismiss` budget, so a multi-UTXO NIGHT
    /// move funded there would overrun it and the node would dismiss the tx. The recipient output
    /// therefore sits on the maker intent's fallible offer, where the balancer funds it in-segment.
    #[test]
    fn make_transfer_night_output_rides_the_fallible_offer() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let tx = build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let Transaction::Standard(stx) = &tx else {
            panic!("expected a Standard transaction");
        };
        let intent = stx
            .intents
            .get(&MAKE_TRANSFER_INTENT_SEGMENT)
            .expect("the maker intent rides the fallible segment");
        assert!(
            intent.guaranteed_unshielded_offer.is_none(),
            "unshielded NIGHT movement must not ride the guaranteed offer (time_to_dismiss budget)"
        );
        assert!(
            intent.fallible_unshielded_offer.is_some(),
            "the NIGHT output rides the maker intent's fallible offer"
        );
    }

    /// A valid preview *shielded* address — a shielded output carries a real ZK proof, so it exercises
    /// the mock prover (an unshielded output has no proof to size).
    fn preview_shielded_address() -> String {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        blob.extend_from_slice(&[0x33u8; 32]);
        MidnightSigner::preview()
            .derive_addresses(&blob)
            .expect("derive addresses")
            .shielded
    }

    /// Regression guard for the effect-sizing prover: `mock_prove_unsealed` must yield the **unsealed**
    /// proven form (`proof,embedded-fr`) that the balancer and merge fee sizing consume — the plain ledger
    /// `mock_prove` seals to `proof,pedersen-schnorr`, which cannot re-parse as unsealed and so silently
    /// breaks the whole make* effects path. Uses a shielded output so a real output proof is mock-sized.
    #[test]
    fn mock_prove_unsealed_yields_unsealed_proven_not_sealed() {
        use midnight_ledger::structure::ProofMarker;
        use midnight_serialize::tagged_deserialize;
        type UnsealedProven = Transaction<MnSig, ProofMarker, PedersenRandomness, InMemoryDB>;

        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Shielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_shielded_address(),
            }],
            pay_fees: true,
        };
        let preimage =
            build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");

        // The plain ledger mock seals: its output is tagged pedersen-schnorr and must NOT parse as unsealed.
        let sealed = preimage.mock_prove().expect("mock_prove");
        let mut sealed_bytes = Vec::new();
        tagged_serialize(&sealed, &mut sealed_bytes).unwrap();
        assert!(
            tagged_deserialize::<UnsealedProven>(&mut &sealed_bytes[..]).is_err(),
            "mock_prove output is sealed and must not re-parse as unsealed proven"
        );

        // The effect-sizing prover keeps it unsealed: its output round-trips as embedded-fr.
        let unsealed = mock_prove_unsealed(preimage).expect("mock_prove_unsealed");
        let mut unsealed_bytes = Vec::new();
        tagged_serialize(&unsealed, &mut unsealed_bytes).unwrap();
        let back: UnsealedProven = tagged_deserialize(&mut &unsealed_bytes[..])
            .expect("mock_prove_unsealed output must re-parse as unsealed proven (embedded-fr)");
        assert!(matches!(back, Transaction::Standard(_)));
    }

    /// `authorize` swaps real proofs only into the transaction the policy seam saw: the comparison
    /// ignores proofs, so the planned preimage proven again matches, while a rebuilt preimage (fresh
    /// output randomness, so different commitments) does not.
    #[test]
    fn proofs_are_swapped_only_into_the_planned_transaction() {
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Shielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: preview_shielded_address(),
            }],
            pay_fees: true,
        };
        let standard = |tx| match tx {
            Transaction::Standard(stx) => stx,
            Transaction::ClaimRewards(_) => panic!("not a standard transaction"),
        };
        let preimage =
            build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let planned = standard(mock_prove_unsealed(preimage.clone()).unwrap());
        let proven_again = standard(mock_prove_unsealed(preimage).unwrap());
        assert!(crate::balance_tx::same_apart_from_proofs(
            &planned,
            &proven_again
        ));

        let rebuilt =
            build_make_transfer_preimage("midnight:preview", &req).expect("build preimage");
        let rebuilt = standard(mock_prove_unsealed(rebuilt).unwrap());
        assert!(!crate::balance_tx::same_apart_from_proofs(
            &planned, &rebuilt
        ));
    }

    /// `authorize` proves the planned outputs and spends the planned balancing as it stands: the
    /// wallet's NIGHT coin and change in the transfer's fallible segment, a DUST fee of exactly the
    /// planned amount, and the planned TTL. The vault names an indexer nothing listens on, so an
    /// authorize that re-synced would fail, and a loopback proof server proves the DUST spend.
    #[test]
    fn authorize_spends_exactly_the_planned_transfer() {
        use midnight_base_crypto::hash::HashOutput;
        use midnight_base_crypto::time::Timestamp;
        use midnight_coin_structure::coin::{UserAddress, NIGHT};
        use midnight_ledger::structure::{IntentHash, UtxoSpend};
        use midnight_serialize::tagged_deserialize;

        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x44u8; 32]);
        blob.extend_from_slice(&[0x55u8; 32]);
        blob.extend_from_slice(&[0x66u8; 32]);
        let provider = MidnightSigner::preview()
            .crypto_provider(&ows_signer::SecretBytes::new(blob))
            .unwrap();
        let vault = crate::mock_prover::vault("midnight:preview", "planned-transfer");
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 250,
                recipient: preview_unshielded_address(),
            }],
            pay_fees: true,
        };
        let preimage = build_make_transfer_preimage("midnight:preview", &req).unwrap();
        let Transaction::Standard(base) = mock_prove_unsealed(preimage.clone()).unwrap() else {
            panic!("not a standard transaction");
        };

        // The wallet funds the 250 from a 300 coin, with 50 back, inside the transfer's fallible offer.
        let vk = provider.unshielded_verifying_key().unwrap();
        let mut outputs: Vec<UtxoOutput> = base
            .intents
            .get(&MAKE_TRANSFER_INTENT_SEGMENT)
            .and_then(|intent| intent.fallible_unshielded_offer.clone())
            .map(|offer| offer.outputs.iter_deref().cloned().collect())
            .unwrap();
        outputs.push(UtxoOutput {
            value: 50,
            owner: UserAddress::from(vk.clone()),
            type_: NIGHT,
        });
        outputs.sort();
        let inputs = vec![UtxoSpend {
            value: 300,
            owner: vk,
            type_: NIGHT,
            intent_hash: IntentHash(HashOutput([1; 32])),
            output_no: 0,
        }];
        let funding = UnshieldedOffer {
            inputs: inputs.clone().into(),
            outputs: outputs.clone().into(),
            signatures: vec![].into(),
        };
        let ttl = Timestamp::from_secs(3_600);
        let plan = crate::BalancedPlan::spending_dust(
            base,
            MAKE_TRANSFER_INTENT_SEGMENT,
            vec![(MAKE_TRANSFER_INTENT_SEGMENT, funding)],
            ttl,
            42,
            Timestamp::from_secs(4_600),
            crate::balance_tx::dust_state_with_one_note(
                &[0x66; 32],
                midnight_ledger::structure::STARS_PER_NIGHT,
                Timestamp::from_secs(1_000),
            ),
        );

        let signable = authorize(
            "midnight:preview",
            &provider,
            TransferPlan { preimage, plan },
            Some(&vault),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&vault);
        let Transaction::Standard(stx) =
            tagged_deserialize::<super::super::build::ProvenTx>(&mut &signable[..]).unwrap()
        else {
            panic!("not a standard transaction");
        };
        assert_eq!(stx.intents.iter().count(), 1);
        let intent = stx.intents.get(&MAKE_TRANSFER_INTENT_SEGMENT).unwrap();
        assert!(intent.guaranteed_unshielded_offer.is_none());
        let leg = intent.fallible_unshielded_offer.as_ref().unwrap();
        assert_eq!(leg.inputs.iter_deref().cloned().collect::<Vec<_>>(), inputs);
        assert_eq!(
            leg.outputs.iter_deref().cloned().collect::<Vec<_>>(),
            outputs
        );
        assert_eq!(intent.ttl, ttl);
        let dust = intent.dust_actions.as_ref().unwrap();
        assert_eq!(dust.spends.iter_deref().map(|s| s.v_fee).sum::<u128>(), 42);
        assert!(
            dust.spends
                .iter_deref()
                .all(|s| s.proof.0.iter().all(|b| *b == 0xde)),
            "proved by the vault's proof server"
        );
    }

    #[test]
    fn rejects_recipient_with_wrong_network_hrp() {
        // A mainnet-HRP address handed to a preview transfer is rejected at decode time.
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11u8; 32]);
        blob.extend_from_slice(&[0x22u8; 32]);
        blob.extend_from_slice(&[0x33u8; 32]);
        let mainnet_addr = MidnightSigner::mainnet()
            .derive_addresses(&blob)
            .unwrap()
            .unshielded;
        let req = MakeTransferRequest {
            desired_outputs: vec![DesiredOutput {
                kind: TransferKind::Unshielded,
                token_type: "night".into(),
                value: 1_000,
                recipient: mainnet_addr,
            }],
            pay_fees: true,
        };
        assert!(build_make_transfer_preimage("midnight:preview", &req).is_err());
    }
}
