use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianConfig {
    pub wallet_id: String,
    pub wallet_name: String,
    pub threshold: u8,
    pub total_guardians: u8,
    pub secret_hash: String,
    pub guardians: Vec<Guardian>,
    pub created_at: String,
    pub dead_mans_switch: Option<DeadMansSwitchConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    pub id: String,
    pub name: String,
    pub can_freeze: bool,
    pub encrypted_shard: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub wallet_id: String,
    pub initiated_by: String,
    pub initiated_at: String,
    pub time_lock_until: String,
    pub status: RecoveryStatus,
    pub submitted_shards: Vec<SubmittedShard>,
    pub threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryStatus {
    Pending,
    ThresholdMet,
    Completed,
    Cancelled,
    Frozen,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmittedShard {
    pub guardian_id: String,
    pub shard_data: Vec<u8>,
    pub submitted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadMansSwitchConfig {
    pub inactivity_days: u64,
    pub last_heartbeat: String,
    pub beneficiaries: Vec<Beneficiary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Beneficiary {
    pub name: String,
    pub guardian_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianInput {
    pub name: String,
    pub passphrase: String,
    #[serde(default)]
    pub can_freeze: bool,
}
