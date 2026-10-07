use serde::Serialize;

use ows_core::Config;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    /// The wallet the operation acted on. Absent only for **vault-scoped** operations — registering
    /// or deleting a policy — which belong to no single wallet; every wallet-scoped operation carries
    /// it, and it is always the wallet's **id**, never its (renameable) name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_id: Option<String>,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Append an audit entry to the audit log.
/// Creates the log directory and file if they don't exist.
/// Silently ignores write failures (audit should not break operations).
pub fn log_audit(entry: &AuditEntry) {
    let config = Config::default();
    let log_dir = config.vault_path.join("logs");
    let log_path = log_dir.join("audit.jsonl");

    let _ = fs::create_dir_all(&log_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
    }

    if let Ok(json) = serde_json::to_string(entry) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{}", json);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// Generic wallet event logger. All wallet audit helpers delegate here.
pub fn log_wallet_event(
    wallet_id: &str,
    operation: &str,
    chain_id: Option<&str>,
    address: Option<&str>,
    details: Option<String>,
) {
    log_audit(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        wallet_id: Some(wallet_id.to_string()),
        operation: operation.to_string(),
        chain_id: chain_id.map(String::from),
        address: address.map(String::from),
        details,
    });
}

/// Generic vault-scoped event logger, for operations that belong to the vault rather than to any one
/// wallet — policy registration and deletion.
pub fn log_vault_event(operation: &str, details: Option<String>) {
    log_audit(&AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        wallet_id: None,
        operation: operation.to_string(),
        chain_id: None,
        address: None,
        details,
    });
}

/// How the caller proved its authority for a signing operation, recorded so the trail separates what
/// a human did from what an autonomous agent did under a minted token.
pub enum Actor {
    /// The wallet owner's envelope passphrase — full authority, no policy gate.
    Owner,
    /// An `ows_key_…` API token — policy-gated. The token itself is never recorded.
    ApiKey,
}

impl Actor {
    /// Classify the credential the CLI is about to use. Reads only the token *prefix*; the value
    /// never reaches an audit record.
    pub fn from_passphrase(passphrase: Option<&str>) -> Self {
        if passphrase.is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX)) {
            Actor::ApiKey
        } else {
            Actor::Owner
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Actor::Owner => "owner",
            Actor::ApiKey => "api_key",
        }
    }
}

/// The verdict a policy-gated operation reached. Recorded under the **same** operation name as a
/// successful one, so an allow and a deny sit side by side in the trail and a refused attempt is not
/// simply an absence.
pub enum Outcome<'a> {
    Allowed,
    Denied { policy_id: &'a str, reason: &'a str },
}

/// Longest policy-supplied `reason` an audit record carries. The text comes from an executable
/// policy's own output, so it is bounded here rather than trusted to be short.
const MAX_REASON: usize = 500;

impl Outcome<'_> {
    fn describe(&self) -> String {
        match self {
            Outcome::Allowed => "outcome=allowed".to_string(),
            Outcome::Denied { policy_id, reason } => {
                let reason = if reason.len() > MAX_REASON {
                    format!("{}…", &reason[..MAX_REASON])
                } else {
                    (*reason).to_string()
                };
                format!("outcome=denied, policy={policy_id}, reason={reason}")
            }
        }
    }
}

/// Classify a policy-gated call's error as a policy verdict, or `None` when it is not one.
///
/// Only `PolicyDenied` is a verdict. Every other error — a network failure, a malformed request, a
/// missing prover — is the operation failing rather than a policy deciding, and recording those would
/// turn the audit trail into an error log.
pub fn denial(err: &ows_lib::OwsLibError) -> Option<Outcome<'_>> {
    match err {
        ows_lib::OwsLibError::Core(ows_core::OwsError::PolicyDenied { policy_id, reason }) => {
            Some(Outcome::Denied { policy_id, reason })
        }
        _ => None,
    }
}

/// Convenience: log a wallet creation event with all accounts.
pub fn log_wallet_created(info: &ows_lib::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, "create_wallet", None, None, Some(details));
}

/// Convenience: log a wallet import event with all accounts.
pub fn log_wallet_imported(info: &ows_lib::WalletInfo) {
    let details = info
        .accounts
        .iter()
        .map(|a| format!("{}={}", a.chain_id, a.address))
        .collect::<Vec<_>>()
        .join(", ");
    log_wallet_event(&info.id, "import_wallet", None, None, Some(details));
}

/// Convenience: log a wallet export event.
pub fn log_wallet_exported(wallet_id: &str) {
    log_wallet_event(wallet_id, "export_wallet", None, None, None);
}

/// Convenience: log a wallet deletion event.
pub fn log_wallet_deleted(wallet_id: &str, name: &str) {
    log_wallet_event(
        wallet_id,
        "delete_wallet",
        None,
        None,
        Some(format!("name={name}")),
    );
}

/// Convenience: log a wallet rename event.
pub fn log_wallet_renamed(wallet_id: &str, old_name: &str, new_name: &str) {
    log_wallet_event(
        wallet_id,
        "rename_wallet",
        None,
        None,
        Some(format!("{old_name} -> {new_name}")),
    );
}

/// Convenience: log a broadcast event.
pub fn log_broadcast(wallet_id: &str, chain_id: &str, tx_hash: &str) {
    log_wallet_event(
        wallet_id,
        "broadcast_transaction",
        Some(chain_id),
        None,
        Some(format!("tx_hash={tx_hash}")),
    );
}

/// Convenience: log a transaction signing that produced a signature but broadcast nothing. The
/// artifact leaves the wallet and can be submitted by anyone holding it — on Midnight `sign tx`
/// returns a fully sealed, submittable transaction — so it is traced in its own right, separately
/// from any later `broadcast_transaction`.
pub fn log_transaction_signed(wallet_id: &str, chain_id: &str, actor: &Actor, outcome: &Outcome) {
    log_wallet_event(
        wallet_id,
        "sign_transaction",
        Some(chain_id),
        None,
        Some(format!("actor={}, {}", actor.as_str(), outcome.describe())),
    );
}

/// Convenience: log a message or typed-data signing. `kind` distinguishes the two, since a typed-data
/// signature can authorize on-chain value movement.
pub fn log_message_signed(
    wallet_id: &str,
    chain_id: &str,
    kind: &str,
    actor: &Actor,
    outcome: &Outcome,
) {
    log_wallet_event(
        wallet_id,
        "sign_message",
        Some(chain_id),
        None,
        Some(format!(
            "kind={kind}, actor={}, {}",
            actor.as_str(),
            outcome.describe()
        )),
    );
}

/// Convenience: log an API key minting, once per wallet the key was granted — the key is what turns
/// a policy into enforcement, so the trail records which wallets it reaches and under which policies.
/// The token is never recorded.
pub fn log_api_key_created(key_id: &str, name: &str, wallet_ids: &[String], policy_ids: &[String]) {
    let policies = if policy_ids.is_empty() {
        "none".to_string()
    } else {
        policy_ids.join(" ")
    };
    for wallet_id in wallet_ids {
        log_wallet_event(
            wallet_id,
            "create_api_key",
            None,
            None,
            Some(format!("key_id={key_id}, name={name}, policies={policies}")),
        );
    }
}

/// Convenience: log an API key revocation, once per wallet the key reached.
pub fn log_api_key_revoked(key_id: &str, name: &str, wallet_ids: &[String]) {
    for wallet_id in wallet_ids {
        log_wallet_event(
            wallet_id,
            "revoke_api_key",
            None,
            None,
            Some(format!("key_id={key_id}, name={name}")),
        );
    }
}

/// Convenience: log a policy registration — vault-scoped, since a policy belongs to no single wallet
/// until a key mints it in.
pub fn log_policy_registered(policy_id: &str, name: &str, rule_count: usize, executable: bool) {
    log_vault_event(
        "create_policy",
        Some(format!(
            "policy_id={policy_id}, name={name}, rules={rule_count}, executable={executable}"
        )),
    );
}

/// Convenience: log a policy deletion. Every key naming the deleted policy stops working (enforcement
/// fails closed), so this is a trail of why those keys began to fail.
pub fn log_policy_deleted(policy_id: &str, name: &str) {
    log_vault_event(
        "delete_policy",
        Some(format!("policy_id={policy_id}, name={name}")),
    );
}

/// Append an audit entry to the audit log at a specific vault path.
/// Like `log_audit` but allows specifying the vault directory (for testing).
#[cfg(test)]
pub fn log_audit_at(entry: &AuditEntry, vault_path: &std::path::Path) {
    let log_dir = vault_path.join("logs");
    let log_path = log_dir.join("audit.jsonl");

    let _ = fs::create_dir_all(&log_dir);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o700));
    }

    if let Ok(json) = serde_json::to_string(entry) {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
            let _ = writeln!(file, "{}", json);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    #[test]
    fn char_audit_entry_written_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: Some("test-wallet-id".to_string()),
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: Some("test details".to_string()),
        };

        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        assert!(log_path.exists(), "audit log file should exist");

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["wallet_id"], "test-wallet-id");
        assert_eq!(parsed["operation"], "create_wallet");
        assert_eq!(parsed["details"], "test details");
        assert_eq!(parsed["timestamp"], "2026-03-22T10:00:00Z");
    }

    #[test]
    fn char_audit_multiple_entries_appended() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        for i in 0..3 {
            let entry = AuditEntry {
                timestamp: format!("2026-03-22T10:0{}:00Z", i),
                wallet_id: Some(format!("wallet-{i}")),
                operation: "create_wallet".to_string(),
                chain_id: None,
                address: None,
                details: None,
            };
            log_audit_at(&entry, vault);
        }

        let log_path = vault.join("logs/audit.jsonl");
        let file = std::fs::File::open(&log_path).unwrap();
        let lines: Vec<String> = std::io::BufReader::new(file)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(lines.len(), 3, "should have 3 audit entries");

        // Verify each line is valid JSON
        for (i, line) in lines.iter().enumerate() {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["wallet_id"], format!("wallet-{i}"));
        }
    }

    #[test]
    fn char_audit_broadcast_entry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            wallet_id: Some("bc-wallet".to_string()),
            operation: "broadcast_transaction".to_string(),
            chain_id: Some("eip155:8453".to_string()),
            address: None,
            details: Some("tx_hash=0xabc123".to_string()),
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed["operation"], "broadcast_transaction");
        assert_eq!(parsed["chain_id"], "eip155:8453");
        assert!(parsed["details"]
            .as_str()
            .unwrap()
            .contains("tx_hash=0xabc123"));
    }

    #[test]
    fn char_audit_entry_skips_none_fields() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: Some("w1".to_string()),
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();

        // Optional None fields should not be serialized
        assert!(parsed.get("chain_id").is_none());
        assert!(parsed.get("address").is_none());
        assert!(parsed.get("details").is_none());
    }

    /// A vault-scoped record (a policy operation) omits `wallet_id` entirely rather than carrying a
    /// placeholder, so a per-wallet query over the log never picks it up.
    #[test]
    fn vault_scoped_entry_omits_the_wallet_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: None,
            operation: "create_policy".to_string(),
            chain_id: None,
            address: None,
            details: Some("policy_id=cap, name=Movement cap".to_string()),
        };
        log_audit_at(&entry, vault);

        let contents = std::fs::read_to_string(vault.join("logs/audit.jsonl")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert!(parsed.get("wallet_id").is_none());
        assert_eq!(parsed["operation"], "create_policy");
    }

    /// The actor classification reads only the token *prefix* — an audit record says whether an agent
    /// or the owner acted, and never carries the credential itself.
    #[test]
    fn actor_classifies_the_credential_without_recording_it() {
        let token = format!("{}deadbeef", ows_lib::key_store::TOKEN_PREFIX);
        assert_eq!(Actor::from_passphrase(Some(&token)).as_str(), "api_key");
        assert_eq!(Actor::from_passphrase(Some("hunter2")).as_str(), "owner");
        assert_eq!(Actor::from_passphrase(None).as_str(), "owner");
    }

    /// Only a `PolicyDenied` is a policy verdict. Any other failure is the operation breaking, not a
    /// policy deciding — recording those would turn the trail into an error log.
    #[test]
    fn only_a_policy_denial_counts_as_a_verdict() {
        let denied = ows_lib::OwsLibError::Core(ows_core::OwsError::PolicyDenied {
            policy_id: "cap".into(),
            reason: "summed movement 5000000 (cap 1000000)".into(),
        });
        let described = denial(&denied).expect("a denial is a verdict").describe();
        assert!(described.contains("outcome=denied"));
        assert!(described.contains("policy=cap"));
        assert!(described.contains("summed movement 5000000"));

        let broken = ows_lib::OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound);
        assert!(denial(&broken).is_none(), "a failure is not a verdict");
    }

    /// A policy's `reason` is text the policy author controls, so the record bounds it instead of
    /// trusting it to be short.
    #[test]
    fn a_long_policy_reason_is_truncated() {
        let denied = ows_lib::OwsLibError::Core(ows_core::OwsError::PolicyDenied {
            policy_id: "verbose".into(),
            reason: "x".repeat(MAX_REASON * 3),
        });
        let described = denial(&denied).unwrap().describe();
        assert!(described.ends_with('…'));
        assert!(described.len() < MAX_REASON * 2);
    }

    #[cfg(unix)]
    #[test]
    fn char_audit_read_only_dir_does_not_panic() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        // Create logs dir as read-only
        let log_dir = vault.join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: Some("w1".to_string()),
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
        };

        // This should not panic — audit failures are silently ignored
        log_audit_at(&entry, vault);

        // Restore permissions for cleanup
        std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn char_audit_log_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let entry = AuditEntry {
            timestamp: "2026-03-22T10:00:00Z".to_string(),
            wallet_id: Some("w1".to_string()),
            operation: "create_wallet".to_string(),
            chain_id: None,
            address: None,
            details: None,
        };
        log_audit_at(&entry, vault);

        let log_path = vault.join("logs/audit.jsonl");
        let meta = std::fs::metadata(&log_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "audit log file should have 0600 permissions, got {:04o}",
            mode
        );

        let log_dir = vault.join("logs");
        let dir_meta = std::fs::metadata(&log_dir).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "logs directory should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }
}
