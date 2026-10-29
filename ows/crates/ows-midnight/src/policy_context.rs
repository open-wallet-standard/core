//! The `chain_extra` context the second, effect-aware policy pass reads, assembled from an inert
//! [`ConnectorPlan`](crate::ConnectorPlan) before anything is proven. The policy engine receives
//! its serialized form unchanged, so these field names are what an executable policy reads.

use crate::balance_tx::SegmentEffects;
use crate::contracts::ContractInteraction;

/// Everything the policy seam shows a policy about one planned transaction. The two lists are kept
/// disjoint: `segment_effects` is how much the *wallet* moves, `contracts` is *who* the transaction
/// talks to and how much value each contract declares. `fee` and `dust_registrations` describe the
/// wallet's own fee section and the authority over DUST generation it signs away.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicyContext {
    pub segment_effects: Vec<SegmentEffects>,
    pub contracts: Vec<ContractInteraction>,
    pub fee: FeeContext,
    pub dust_registrations: Vec<DustRegistrationContext>,
}

/// How the wallet pays the transaction's DUST fee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FeeMode {
    /// No fee section: fees are off, or the wallet is the maker of an offer the taker pays for.
    None,
    /// A generationless registration of the wallet's unregistered NIGHT, listed in
    /// `dust_registrations`.
    Registration,
    /// A proof-bearing spend of DUST the wallet already holds.
    Spend,
}

/// The wallet's own DUST fee section.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FeeContext {
    pub mode: FeeMode,
    /// The most DUST the fee can take, as a decimal string. A spend takes exactly its `v_fee`. A
    /// registration takes at most its `allow_fee_payment`, drawn from the generationless DUST of the
    /// NIGHT it registers, which the wallet would otherwise be credited with; the wallet's held DUST
    /// does not drop, so `segment_effects` shows no DUST for it.
    pub dust_burned: String,
}

impl FeeContext {
    pub(crate) fn none() -> Self {
        Self {
            mode: FeeMode::None,
            dust_burned: "0".to_string(),
        }
    }

    pub(crate) fn registration(allow_fee_payment: u128) -> Self {
        Self {
            mode: FeeMode::Registration,
            dust_burned: allow_fee_payment.to_string(),
        }
    }

    pub(crate) fn spend(fee_dust: u128) -> Self {
        Self {
            mode: FeeMode::Spend,
            dust_burned: fee_dust.to_string(),
        }
    }
}

/// One dust registration the wallet signs. On chain it points the NIGHT key's DUST generation at
/// `dust_address`, replacing wherever it pointed before, and lets the fee draw up to
/// `allow_fee_payment` from the generationless DUST of the NIGHT its intent spends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DustRegistrationContext {
    /// The intent that carries it. Dust actions apply before any segment executes, whichever intent
    /// carries them.
    pub intent_id: u16,
    /// Whether the dapp's transaction carried it; `false` for the wallet's own fee registration.
    pub carried: bool,
    /// The unshielded address of the NIGHT key it registers.
    pub night_address: String,
    /// The DUST address that NIGHT will generate to.
    pub dust_address: String,
    /// Whether `dust_address` is the wallet's own. The wallet refuses to sign a registration to any
    /// other, so this is always `true` today.
    pub own: bool,
    pub allow_fee_payment: String,
    /// Whether it moves an existing delegation of the NIGHT key to a different DUST address: `null`
    /// when that is unknown. It is always unknown today: the indexer reports whether a NIGHT coin
    /// generates DUST, not which DUST address its key is delegated to.
    pub replaces_delegation: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::ContractActionKind;
    use ows_core::policy::TransactionEffect;

    /// Policy programs index into these keys, so the serialized shape is the contract.
    #[test]
    fn segment_effects_and_contracts_keep_their_published_shape() {
        let context = PolicyContext {
            segment_effects: vec![SegmentEffects {
                segment: 0,
                effects: vec![TransactionEffect {
                    address: "mn_addr1wallet".to_string(),
                    diff: vec![("00".repeat(32), "-5".to_string())],
                }],
            }],
            contracts: vec![ContractInteraction {
                segment: 3,
                kind: ContractActionKind::Call,
                address: "ab".repeat(32),
                entry_point: Some("swap".to_string()),
                sent_to: vec![("00".repeat(32), "5".to_string())],
                received_from: vec![],
            }],
            fee: FeeContext::none(),
            dust_registrations: vec![],
        };

        let json = serde_json::to_value(&context).unwrap();

        assert_eq!(
            json["segment_effects"][0],
            serde_json::json!({
                "segment": 0,
                "effects": [{ "address": "mn_addr1wallet", "diff": [["00".repeat(32), "-5"]] }],
            })
        );
        assert_eq!(
            json["contracts"][0],
            serde_json::json!({
                "segment": 3,
                "kind": "call",
                "address": "ab".repeat(32),
                "entry_point": "swap",
                "sent_to": [["00".repeat(32), "5"]],
                "received_from": [],
            })
        );
    }

    #[test]
    fn the_fee_and_its_registration_serialize_as_documented() {
        let context = PolicyContext {
            segment_effects: vec![],
            contracts: vec![],
            fee: FeeContext::registration(60_000),
            dust_registrations: vec![DustRegistrationContext {
                intent_id: 2,
                carried: false,
                night_address: "mn_addr1wallet".to_string(),
                dust_address: "mn_dust1wallet".to_string(),
                own: true,
                allow_fee_payment: "60000".to_string(),
                replaces_delegation: None,
            }],
        };

        let json = serde_json::to_value(&context).unwrap();

        assert_eq!(
            json["fee"],
            serde_json::json!({ "mode": "registration", "dust_burned": "60000" })
        );
        assert_eq!(
            json["dust_registrations"],
            serde_json::json!([{
                "intent_id": 2,
                "carried": false,
                "night_address": "mn_addr1wallet",
                "dust_address": "mn_dust1wallet",
                "own": true,
                "allow_fee_payment": "60000",
                "replaces_delegation": null,
            }])
        );
        assert_eq!(
            serde_json::to_value(FeeContext::spend(7)).unwrap(),
            serde_json::json!({ "mode": "spend", "dust_burned": "7" })
        );
        assert_eq!(
            serde_json::to_value(FeeContext::none()).unwrap(),
            serde_json::json!({ "mode": "none", "dust_burned": "0" })
        );
    }
}
