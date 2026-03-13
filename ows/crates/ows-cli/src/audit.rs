use serde::Serialize;

use ows_core::Config;
use std::fs::{self, OpenOptions};
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub wallet_id: String,
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
        wallet_id: wallet_id.to_string(),
        operation: operation.to_string(),
        chain_id: chain_id.map(String::from),
        address: address.map(String::from),
        details,
    });
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
