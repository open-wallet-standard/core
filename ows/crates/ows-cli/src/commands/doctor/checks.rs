//! Individual diagnostic checks for `ows doctor`.

use crate::commands::doctor::report::{DoctorCheckId, DoctorFinding, DoctorReport};

use ows_core::Config;

// ---------------------------------------------------------------------------
// Check IDs
// ---------------------------------------------------------------------------

/// Vault path resolution check ID.
pub const CHECK_VAULT_PATH: DoctorCheckId = DoctorCheckId::new("vault.path");
/// Vault existence check ID.
pub const CHECK_VAULT_EXISTS: DoctorCheckId = DoctorCheckId::new("vault.exists");
/// Wallets directory presence check ID.
pub const CHECK_WALLETS_DIR: DoctorCheckId = DoctorCheckId::new("vault.wallets_dir");
/// Keys directory presence check ID.
pub const CHECK_KEYS_DIR: DoctorCheckId = DoctorCheckId::new("vault.keys_dir");
/// Policies directory presence check ID.
pub const CHECK_POLICIES_DIR: DoctorCheckId = DoctorCheckId::new("vault.policies_dir");
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

/// Resolve the vault path, using an override for testing purposes.
///
/// When `vault_path_override` is `None`, resolves from `Config::default()`.
/// Tests can pass a specific path to avoid environment variable dependence.
fn resolve_vault_path(vault_path_override: Option<&std::path::Path>) -> std::path::PathBuf {
    match vault_path_override {
        Some(p) => p.to_path_buf(),
        None => Config::default().vault_path,
    }
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

    let vault_path = resolve_vault_path(None);

    findings.push(DoctorFinding::ok(
        CHECK_VAULT_PATH,
        "Vault path resolved",
        &format!("Vault path resolved to `{}`", vault_path.display()),
    ));

    findings
}

/// Check that the vault directory exists.
pub fn check_vault_exists() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path(None);

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

/// Check that the wallets subdirectory exists (if vault exists).
pub fn check_wallets_dir() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path(None);

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_WALLETS_DIR,
            "Wallets directory skipped",
            "Vault does not exist; skipping wallets directory check.",
        )];
    }

    let wallets_dir = vault_path.join("wallets");

    if wallets_dir.exists() {
        // Count wallet files
        let wallet_count = std::fs::read_dir(&wallets_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0);

        vec![DoctorFinding::ok(
            CHECK_WALLETS_DIR,
            "Wallets directory present",
            &format!(
                "wallets/ exists with {} wallet file(s)",
                wallet_count
            ),
        )
        .with_path(wallets_dir)]
    } else {
        vec![DoctorFinding::error(
            CHECK_WALLETS_DIR,
            "Wallets directory missing",
            &format!(
                "Expected `{}` but it does not exist.",
                wallets_dir.display()
            ),
            "This is unexpected. The wallet command should create this directory.",
        )
        .with_path(wallets_dir)]
    }
}

/// Check that the keys subdirectory exists (if vault exists).
pub fn check_keys_dir() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path(None);

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_KEYS_DIR,
            "Keys directory skipped",
            "Vault does not exist; skipping keys directory check.",
        )];
    }

    let keys_dir = vault_path.join("keys");

    if keys_dir.exists() {
        vec![DoctorFinding::ok(
            CHECK_KEYS_DIR,
            "Keys directory present",
            &format!("keys/ exists at `{}`", keys_dir.display()),
        )
        .with_path(keys_dir)]
    } else {
        vec![DoctorFinding::skipped(
            CHECK_KEYS_DIR,
            "Keys directory not present",
            "keys/ does not exist. No API keys have been created yet.",
        )]
    }
}

/// Check that the policies subdirectory exists (if vault exists).
pub fn check_policies_dir() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path(None);

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_POLICIES_DIR,
            "Policies directory skipped",
            "Vault does not exist; skipping policies directory check.",
        )];
    }

    let policies_dir = vault_path.join("policies");

    if policies_dir.exists() {
        vec![DoctorFinding::ok(
            CHECK_POLICIES_DIR,
            "Policies directory present",
            &format!("policies/ exists at `{}`", policies_dir.display()),
        )
        .with_path(policies_dir)]
    } else {
        vec![DoctorFinding::skipped(
            CHECK_POLICIES_DIR,
            "Policies directory not present",
            "policies/ does not exist. No policies have been created yet.",
        )]
    }
}

/// Check that the logs subdirectory exists (if vault exists).
pub fn check_logs_dir() -> Vec<DoctorFinding> {
    let vault_path = resolve_vault_path(None);

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
    let config_path = resolve_vault_path(None).join("config.json");

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

    let vault_path = resolve_vault_path(None);

    if !vault_path.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_VAULT_PERMS,
            "Permissions check skipped",
            "Vault does not exist; skipping permissions check.",
        )];
    }

    let mut findings = Vec::new();

    // Check vault directory permissions
    if let Ok(meta) = std::fs::metadata(vault_path) {
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
        // No findings means we didn't add anything above
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

/// Run all V1 diagnostic checks and return the aggregated report.
///
/// Checks run in a fixed order. Each check is independent and produces
/// zero or more findings. All findings are collected into a single report.
pub fn run_all_checks() -> DoctorReport {
    let mut all_findings = Vec::new();

    // Path resolution and HOME check
    all_findings.extend(check_vault_path());

    // Vault existence
    all_findings.extend(check_vault_exists());

    // Required directories
    all_findings.extend(check_wallets_dir());
    all_findings.extend(check_keys_dir());
    all_findings.extend(check_policies_dir());
    all_findings.extend(check_logs_dir());

    // Config
    all_findings.extend(check_config());

    // Permissions (platform-specific)
    all_findings.extend(check_vault_permissions());

    DoctorReport::new(all_findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::DoctorStatus;
    use tempfile::TempDir;

    #[test]
    fn test_check_vault_path_includes_home_check() {
        let findings = check_vault_path();
        // Should have at least 2 findings: HOME check + vault path
        assert!(findings.len() >= 2);

        // Should have CHECK_VAULT_PATH finding
        let path_finding = findings.iter().find(|f| f.id == CHECK_VAULT_PATH);
        assert!(path_finding.is_some());
        assert_eq!(path_finding.unwrap().status, DoctorStatus::Ok);
    }

    #[test]
    fn test_check_vault_exists_not_found() {
        // Use a path that definitely doesn't exist
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_vault_exists();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, CHECK_VAULT_EXISTS);
        assert_eq!(finding.status, DoctorStatus::Error);
        assert!(finding.detail.contains("not found"));
    }

    #[test]
    fn test_check_wallets_dir_skipped_when_vault_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_wallets_dir();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_check_keys_dir_skipped_when_vault_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_keys_dir();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_check_policies_dir_skipped_when_vault_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_policies_dir();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_check_logs_dir_skipped_when_vault_missing() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_logs_dir();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_check_config_skipped_when_no_config() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let findings = check_config();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, CHECK_CONFIG);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_check_config_valid() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        // Create a valid config
        let config_path = temp_dir.path().join(".ows/config.json");
        std::fs::create_dir_all(config_path.parent().unwrap()).ok();
        let config_content = serde_json::json!({
            "vault_path": "/test/.ows",
            "rpc": {
                "eip155:1": "https://eth.example.com"
            }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config_content).unwrap()).ok();

        let findings = check_config();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, CHECK_CONFIG);
        assert_eq!(finding.status, DoctorStatus::Ok);
        assert!(finding.detail.contains("1 RPC endpoint"));
    }

    #[test]
    fn test_check_config_malformed() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        // Create a malformed config
        let config_path = temp_dir.path().join(".ows/config.json");
        std::fs::create_dir_all(config_path.parent().unwrap()).ok();
        std::fs::write(&config_path, "{ invalid json }").ok();

        let findings = check_config();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.id, CHECK_CONFIG);
        assert_eq!(finding.status, DoctorStatus::Error);
        assert!(finding.code.is_some());
    }

    #[test]
    fn test_run_all_checks_returns_valid_report() {
        // Use a temporary HOME so we don't affect real vault
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        let report = run_all_checks();

        // Should have findings
        assert!(!report.findings.is_empty());

        // Should have an overall status
        assert!(matches!(
            report.overall_status,
            DoctorStatus::Ok | DoctorStatus::Warning | DoctorStatus::Error | DoctorStatus::Skipped
        ));

        // Exit code should be 0 or 1
        assert!(report.exit_code() >= 0 && report.exit_code() <= 1);
    }

    #[test]
    fn test_check_wallets_dir_with_wallets() {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var("HOME", temp_dir.path());

        // Create vault with wallets
        let vault = temp_dir.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();

        // Add a dummy wallet file
        let wallet_content = serde_json::json!({
            "ows_version": 2,
            "id": "test-wallet",
            "name": "Test Wallet",
            "created_at": "2026-01-01T00:00:00Z",
            "accounts": [],
            "crypto": {},
            "key_type": "mnemonic"
        });
        let wallet_path = wallets_dir.join("test-wallet.json");
        std::fs::write(&wallet_path, serde_json::to_string_pretty(&wallet_content).unwrap()).ok();

        let findings = check_wallets_dir();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.status, DoctorStatus::Ok);
        assert!(finding.detail.contains("1 wallet file"));
    }
}
