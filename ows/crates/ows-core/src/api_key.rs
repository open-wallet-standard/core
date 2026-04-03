use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An API key file stored at `~/.ows/keys/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyFile {
    pub id: String,
    pub name: String,
    /// SHA-256 hash of the raw token (hex-encoded).
    pub token_hash: String,
    pub created_at: String,
    /// Wallet IDs this key can access.
    pub wallet_ids: Vec<String>,
    /// Policy IDs attached to this key (AND semantics).
    pub policy_ids: Vec<String>,
    /// Optional expiry timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Per-wallet encrypted secret copies, keyed by wallet ID.
    /// Each value is a CryptoEnvelope encrypted with HKDF(token).
    pub wallet_secrets: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_file_serde_roundtrip() {
        let key = ApiKeyFile {
            id: "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c".into(),
            name: "claude-agent".into(),
            token_hash: "e3b0c44298fc1c149afbf4c8996fb924".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec!["3198bc9c-6672-5ab3-d995-4942343ae5b6".into()],
            policy_ids: vec!["base-agent-limits".into()],
            expires_at: None,
            wallet_secrets: HashMap::from([(
                "3198bc9c-6672-5ab3-d995-4942343ae5b6".into(),
                serde_json::json!({
                    "cipher": "aes-256-gcm",
                    "cipherparams": { "iv": "aabbccdd" },
                    "ciphertext": "deadbeef",
                    "auth_tag": "cafebabe",
                    "kdf": "hkdf-sha256",
                    "kdfparams": { "dklen": 32, "salt": "0011", "info": "ows-api-key-v1" }
                }),
            )]),
        };

        let json = serde_json::to_string_pretty(&key).unwrap();
        let deserialized: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, key.id);
        assert_eq!(deserialized.name, "claude-agent");
        assert_eq!(deserialized.wallet_ids.len(), 1);
        assert_eq!(deserialized.policy_ids, vec!["base-agent-limits"]);
        assert!(deserialized.expires_at.is_none());
        assert!(deserialized
            .wallet_secrets
            .contains_key("3198bc9c-6672-5ab3-d995-4942343ae5b6"));
    }

    #[test]
    fn test_api_key_file_with_expiry() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "expiring-key".into(),
            token_hash: "abc123".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: Some("2026-04-01T00:00:00Z".into()),
            wallet_secrets: HashMap::new(),
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("expires_at"));
        let deserialized: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.expires_at.as_deref(),
            Some("2026-04-01T00:00:00Z")
        );
    }

    #[test]
    fn test_api_key_file_no_expiry_omits_field() {
        let key = ApiKeyFile {
            id: "test-id".into(),
            name: "no-expiry".into(),
            token_hash: "abc123".into(),
            created_at: "2026-03-22T10:30:00Z".into(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: HashMap::new(),
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(!json.contains("expires_at"));
    }
}
