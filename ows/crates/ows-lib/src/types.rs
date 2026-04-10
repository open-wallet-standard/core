use serde::{Deserialize, Serialize};

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Binding-friendly wallet information (no crypto envelope exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

/// Result from a signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u8>,
}

/// Result from a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}

/// Parameters for EIP-2612 permit signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermitParams {
    /// ERC-20 token contract address.
    pub token: String,
    /// Address to approve.
    pub spender: String,
    /// Amount in token base units (e.g. "1000000" for 1 USDC).
    pub value: String,
    /// Unix timestamp after which the permit is invalid.
    pub deadline: u64,
    /// Permit nonce — auto-fetched from chain if None.
    pub nonce: Option<u64>,
    /// JSON-RPC endpoint for on-chain lookups.
    pub rpc_url: Option<String>,
}

/// Result from an EIP-2612 permit signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermitSignResult {
    pub signature: String,
    pub v: u8,
    pub r: String,
    pub s: String,
}
