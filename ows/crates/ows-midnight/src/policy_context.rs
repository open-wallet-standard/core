//! The `chain_extra` context the second, effect-aware policy pass reads, assembled from an inert
//! [`ConnectorPlan`](crate::ConnectorPlan) before anything is proven. The policy engine receives
//! its serialized form unchanged, so these field names are what an executable policy reads.

use crate::balance_tx::SegmentEffects;
use crate::contracts::ContractInteraction;

/// Everything the policy seam shows a policy about one planned transaction. The two lists are kept
/// disjoint: `segment_effects` is how much the *wallet* moves, `contracts` is *who* the transaction
/// talks to and how much value each contract declares.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PolicyContext {
    pub segment_effects: Vec<SegmentEffects>,
    pub contracts: Vec<ContractInteraction>,
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
}
