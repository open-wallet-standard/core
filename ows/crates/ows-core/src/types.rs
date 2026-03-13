use serde::{Deserialize, Serialize};

/// Unique wallet identifier (UUID v4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WalletId(pub String);

impl Default for WalletId {
    fn default() -> Self {
        WalletId(uuid::Uuid::new_v4().to_string())
    }
}

impl WalletId {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_id_generates_uuid() {
        let id = WalletId::new();
        assert!(!id.0.is_empty());
        assert!(uuid::Uuid::parse_str(&id.0).is_ok());
    }

    #[test]
    fn test_wallet_id_serde() {
        let id = WalletId("test-id".to_string());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"test-id\"");
        let id2: WalletId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }
}
