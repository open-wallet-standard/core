//! Individual diagnostic checks for `ows doctor`.

use crate::commands::doctor::report::{DoctorCheckId, DoctorFinding, DoctorReport};
use crate::commands::doctor::vault_inspector;

use ows_core::Config;

// ---------------------------------------------------------------------------
// Check IDs
// ---------------------------------------------------------------------------

/// Vault path resolution check ID.
pub const CHECK_VAULT_PATH: DoctorCheckId = DoctorCheckId::new("vault.path");
/// Vault existence check ID.
pub const CHECK_VAULT_EXISTS: DoctorCheckId = DoctorCheckId::new("vault.exists");
/// Logs directory presence check ID.
pub const CHECK_LOGS_DIR: DoctorCheckId = DoctorCheckId::new("vault.logs_dir");
/// Config file presence and parseability check ID.
pub const CHECK_CONFIG: DoctorCheckId = DoctorCheckId::new("config.parse");
/// Vault directory permissions check ID (Unix only).
pub const CHECK_VAULT_PERMS: DoctorCheckId = DoctorCheckId::new("vault.permissions");
/// HOME environment variable check ID.
pub const CHECK_HOME_ENV: DoctorCheckId = DoctorCheckId::new("env.home");

// ---------------------------------------------------------------------------
// Vault path resolution
// ---------------------------------------------------------------------------

/// Resolve the vault path from `Config::default()`.
///
/// Exposed for use by vault_inspector functions in tests.
pub fn resolve_vault_path() -> std::path::PathBuf {
    Config::default().vault_path
}

// ---------------------------------------------------------------------------
// Check implementations
// ---------------------------------------------------------------------------

/// Check that HOME is set and the vault path resolves correctly.
pub fn check_vault_path() -> Vec<DoctorFinding> {
    let mut findings = Vec::new();

    let home = std::env::var("HOME").ok();
    if home.is_none() {
        findings.push(DoctorFinding::error(
            CHECK_HOME_ENV,
            "HOME not set",
            "The HOME environment variable is not set. Vault path resolution may be incorrect.",
            "Set HOME to your user directory path.",
        ));
    }

    let vault_path = resolve_vault_path();

    findings.push(DoctorFinding::ok(
        CHECK_VAULT_PATH,
        "Vault path resolved",
        &format!("Vault path resolved to `{}`", vault_path.display()),
    ));

    findings
}

/// Check that the vault directory exists.
pub fn check_vault_exists() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path();

    if vault_path.exists() {
        vec![DoctorFinding::ok(
            CHECK_VAULT_EXISTS,
            "Vault exists",
            &format!("`{}` exists", vault_path.display()),
        )]
    } else {
        vec![DoctorFinding::error(
            CHECK_VAULT_EXISTS,
            "Vault not found",
            &format!(
                "Vault directory not found at `{}`. No wallets have been created yet.",
                vault_path.display()
            ),
            "Run `ows wallet create` to create your first wallet.",
        )
        .with_path(vault_path.clone())]
    }
}

/// Check that the logs subdirectory exists (if vault exists).
pub fn check_logs_dir() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path();

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_LOGS_DIR,
            "Logs directory skipped",
            "Vault does not exist; skipping logs directory check.",
        )];
    }

    let logs_dir = vault_path.join("logs");

    if logs_dir.exists() {
        vec![DoctorFinding::ok(
            CHECK_LOGS_DIR,
            "Logs directory present",
            &format!("logs/ exists at `{}`", logs_dir.display()),
        )
        .with_path(logs_dir)]
    } else {
        vec![DoctorFinding::skipped(
            CHECK_LOGS_DIR,
            "Logs directory not present",
            "logs/ does not exist. Audit logging may not be active.",
        )]
    }
}

/// Check that the config file is present and parseable.
pub fn check_config() -> Vec<DoctorFinding> {
    let config_path = resolve_vault_path().join("config.json");

    if !config_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_CONFIG,
            "Config file not present",
            "No user config file at `~/.ows/config.json`. Using built-in defaults.",
        )];
    }

    // Use Config::load to get proper error handling for malformed JSON
    match Config::load(&config_path) {
        Ok(config) => {
            let rpc_count = config.rpc.len();
            vec![DoctorFinding::ok(
                CHECK_CONFIG,
                "Config valid",
                &format!(
                    "config.json is valid with {} RPC endpoint(s) configured",
                    rpc_count
                ),
            )
            .with_path(config_path)]
        }
        Err(e) => {
            vec![DoctorFinding::error(
                CHECK_CONFIG,
                "Config parse error",
                &format!("config.json exists but failed to parse: {}", e),
                "Backup and recreate `~/.ows/config.json`.",
            )
            .with_path(config_path)
            .with_code("ERR_CONFIG_PARSE")]
        }
    }
}

/// Check vault directory permissions (Unix only).
#[cfg(unix)]
pub fn check_vault_permissions() -> Vec<DoctorFinding> {
    use std::os::unix::fs::PermissionsExt;

    let vault_path = resolve_vault_path();

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_VAULT_PERMS,
            "Permissions check skipped",
            "Vault does not exist; skipping permissions check.",
        )];
    }

    let mut findings = Vec::new();

    // Check vault directory permissions
    if let Ok(meta) = std::fs::metadata(&vault_path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            findings.push(
                DoctorFinding::warning(
                    CHECK_VAULT_PERMS,
                    "Vault permissions too open",
                    &format!(
                        "Vault directory has permissions {:03o}, expected 0700 (owner-only)",
                        mode
                    ),
                    "Run: chmod 700 ~/.ows",
                )
                .with_path(vault_path.clone())
                .with_code("WARN_VAULT_PERMS"),
            );
        } else {
            findings.push(
                DoctorFinding::ok(
                    CHECK_VAULT_PERMS,
                    "Vault permissions correct",
                    "Vault directory has correct permissions (0700).",
                )
                .with_path(vault_path.clone()),
            );
        }
    }

    // Check wallets directory permissions
    let wallets_dir = vault_path.join("wallets");
    if let Ok(meta) = std::fs::metadata(&wallets_dir) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            findings.push(
                DoctorFinding::warning(
                    CHECK_VAULT_PERMS,
                    "Wallets directory permissions too open",
                    &format!(
                        "Wallets directory has permissions {:03o}, expected 0700",
                        mode
                    ),
                    "Run: chmod 700 ~/.ows/wallets",
                )
                .with_path(wallets_dir.clone())
                .with_code("WARN_WALLETS_PERMS"),
            );
        }
    }

    // Check wallet file permissions
    if let Ok(entries) = std::fs::read_dir(&wallets_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(meta) = std::fs::metadata(entry.path()) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o600 {
                        let file_name = entry.file_name().to_string_lossy();
                        findings.push(
                            DoctorFinding::warning(
                                CHECK_VAULT_PERMS,
                                "Wallet file permissions too open",
                                &format!(
                                    "{} has permissions {:03o}, expected 0600",
                                    file_name, mode
                                ),
                                &format!("Run: chmod 600 ~/.ows/wallets/{}", file_name),
                            )
                            .with_path(entry.path())
                            .with_code("WARN_WALLET_FILE_PERMS"),
                        );
                    }
                }
            }
        }
    }

    if findings.is_empty() {
        vec![DoctorFinding::ok(
            CHECK_VAULT_PERMS,
            "Permissions check passed",
            "All vault and wallet permissions are correct.",
        )]
    } else {
        findings
    }
}

/// Check vault directory permissions (Windows stub — no-op).
#[cfg(not(unix))]
pub fn check_vault_permissions() -> Vec<DoctorFinding> {
    vec![DoctorFinding::skipped(
        CHECK_VAULT_PERMS,
        "Permissions check skipped",
        "Permission checks are Unix-only.",
    )]
}

// ---------------------------------------------------------------------------
// Check runner
// ---------------------------------------------------------------------------

/// Run all diagnostic checks and return the aggregated report.
///
/// Checks run in a fixed order. Each check is independent and produces
/// zero or more findings. All findings are collected into a single report.
pub fn run_all_checks() -> DoctorReport {
    let vault_path = resolve_vault_path();

    let mut all_findings = Vec::new();

    // Path resolution and HOME check
    all_findings.extend(check_vault_path());

    // Vault existence
    all_findings.extend(check_vault_exists());

    // Logs directory (optional)
    all_findings.extend(check_logs_dir());

    // Config
    all_findings.extend(check_config());

    // Wallet, key, and policy file inspection
    all_findings.extend(vault_inspector::check_wallet_files(&vault_path));
    all_findings.extend(vault_inspector::check_key_files(&vault_path));
    all_findings.extend(vault_inspector::check_policy_files(&vault_path));

    // Permissions (platform-specific)
    all_findings.extend(check_vault_permissions());

    DoctorReport::new(all_findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::vault_inspector;

    #[test]
    fn test_run_all_checks_returns_valid_report() {
        // Use a temporary vault path
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        std::fs::create_dir(vault.join("wallets")).ok();
        std::fs::create_dir(vault.join("policies")).ok();
        std::fs::create_dir(vault.join("keys")).ok();

        // Add a valid wallet
        let wallet = ows_core::EncryptedWallet::new(
            "test-id".to_string(),
            "Test".to_string(),
            vec![],
            serde_json::json!({}),
            ows_core::KeyType::Mnemonic,
        );
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(vault.join("wallets/test.json"), json).ok();

        // Add a valid policy
        let policy = ows_core::Policy {
            id: "test-policy".to_string(),
            name: "Test".to_string(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            rules: vec![],
            executable: None,
            config: None,
            action: ows_core::PolicyAction::Deny,
        };
        let json = serde_json::to_string_pretty(&policy).unwrap();
        std::fs::write(vault.join("policies/test.json"), json).ok();

        // Run checks with the temp vault path
        std::env::set_var("HOME", temp.path());

        let all_results = vault_inspector::check_wallet_files(&vault);
        assert!(!all_results.is_empty());

        let all_policies = vault_inspector::check_policy_files(&vault);
        assert!(!all_policies.is_empty());

        let all_keys = vault_inspector::check_key_files(&vault);
        assert!(!all_keys.is_empty());

        // Report aggregation
        let mut findings = Vec::new();
        findings.extend(vault_inspector::check_wallet_files(&vault));
        findings.extend(vault_inspector::check_key_files(&vault));
        findings.extend(vault_inspector::check_policy_files(&vault));
        findings.extend(check_config());
        findings.extend(check_logs_dir());

        let report = DoctorReport::new(findings);
        assert!(report.findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_wallet_inspection_empty_dir_warning() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        std::fs::create_dir(vault.join("wallets")).ok();

        let findings = vault_inspector::check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Warning));
    }

    #[test]
    fn test_wallet_inspection_malformed_json() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        std::fs::write(wallets_dir.join("bad.json"), "{ invalid }").ok();

        let findings = vault_inspector::check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.code == Some("ERR_FILE_MALFORMED")));
    }

    #[test]
    fn test_wallet_inspection_valid() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();

        let wallet = ows_core::EncryptedWallet::new(
            "test-wallet".to_string(),
            "Test Wallet".to_string(),
            vec![],
            serde_json::json!({}),
            ows_core::KeyType::Mnemonic,
        );
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(wallets_dir.join("test.json"), json).ok();

        let findings = vault_inspector::check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_policy_inspection_valid() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        let policies_dir = vault.join("policies");
        std::fs::create_dir_all(&policies_dir).ok();

        let policy = ows_core::Policy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            rules: vec![],
            executable: None,
            config: None,
            action: ows_core::PolicyAction::Deny,
        };
        let json = serde_json::to_string_pretty(&policy).unwrap();
        std::fs::write(policies_dir.join("test.json"), json).ok();

        let findings = vault_inspector::check_policy_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_key_inspection_valid() {
        let temp = tempfile::TempDir::new().unwrap();
        let vault = temp.path().to_path_buf();
        let keys_dir = vault.join("keys");
        std::fs::create_dir_all(&keys_dir).ok();

        let key = ows_core::ApiKeyFile {
            id: "test-key".to_string(),
            name: "Test Key".to_string(),
            token_hash: "deadbeef".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: std::collections::HashMap::new(),
        };
        let json = serde_json::to_string_pretty(&key).unwrap();
        std::fs::write(keys_dir.join("test.json"), json).ok();

        let findings = vault_inspector::check_key_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }
}
