//! Read-only vault artifact inspection for `ows doctor`.
//!
//! Provides functions to enumerate and validate wallet, key, and policy files
//! without decrypting secrets or modifying any state.
//!
//! All functions return findings directly; they do not mutate or create files.
//!
//! # Validation approach
//!
//! - **Wallet files**: Deserialize as `EncryptedWallet`. The serde derivation
//!   validates structure. We additionally check for empty ID and empty accounts.
//! - **Key files**: Deserialize as `ApiKeyFile`. Validates all required fields.
//! - **Policy files**: Deserialize as `Policy`. Validates structure.
//!
//! # Error taxonomy
//!
//! | Condition | Status | Code |
//! |-----------|--------|------|
//! | File unreadable (permissions) | Error | `ERR_FILE_UNREADABLE` |
//! | File not valid JSON | Error | `ERR_FILE_MALFORMED` |
//! | JSON parses but schema invalid | Error | `ERR_METADATA_INVALID` |
//! | No artifacts of this type | Skipped | — |
//! | All artifacts valid | Ok | — |
//! | Some artifacts valid, some invalid | Warning | `WARN_ARTIFACTS_CORRUPTED` |

use std::fs;
use std::path::Path;

use ows_core::{ApiKeyFile, EncryptedWallet, Policy};

use crate::commands::doctor::report::{DoctorCheckId, DoctorFinding};

// ---------------------------------------------------------------------------
// Check IDs
// ---------------------------------------------------------------------------

pub const CHECK_WALLET_FILES: DoctorCheckId = DoctorCheckId::new("vault.wallet_files");
pub const CHECK_KEY_FILES: DoctorCheckId = DoctorCheckId::new("vault.key_files");
pub const CHECK_POLICY_FILES: DoctorCheckId = DoctorCheckId::new("vault.policy_files");

// ---------------------------------------------------------------------------
// Wallet file inspection
// ---------------------------------------------------------------------------

/// Inspect all wallet files in the vault.
///
/// Returns one finding per artifact, plus a summary finding.
///
/// # Arguments
/// * `vault_path` - Path to the vault directory (e.g. `~/.ows`)
pub fn check_wallet_files(vault_path: &Path) -> Vec<DoctorFinding> {
    let wallets_dir = vault_path.join("wallets");

    if !wallets_dir.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_WALLET_FILES,
            "No wallets directory",
            "Wallets directory does not exist; skipping wallet inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&wallets_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_WALLET_FILES,
                "Cannot read wallets directory",
                &format!("Wallets directory exists but cannot be read: {}", e),
                "Check directory permissions.",
            )
            .with_path(wallets_dir)
            .with_code("ERR_DIR_UNREADABLE")];
        }
    };

    // Filter to only .json files
    let json_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    if json_entries.is_empty() {
        return vec![DoctorFinding::warning(
            CHECK_WALLET_FILES,
            "No wallets present",
            "No wallet files found in the wallets directory.",
            "Run `ows wallet create` to create your first wallet.",
        )
        .with_path(wallets_dir)
        .with_code("WARN_NO_WALLETS")];
    }

    let mut findings = Vec::new();
    let mut valid_count = 0;
    let mut corrupted_count = 0;

    for entry in json_entries {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        // Try to read the file
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_WALLET_FILES,
                    "Wallet file unreadable",
                    &format!("{}: cannot read file: {}", file_name, e),
                    "Check file permissions.",
                )
                .with_path(path)
                .with_code("ERR_FILE_UNREADABLE"));
                continue;
            }
        };

        // Try to parse as EncryptedWallet
        let wallet: EncryptedWallet = match serde_json::from_str(&contents) {
            Ok(w) => w,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_WALLET_FILES,
                    "Wallet file malformed",
                    &format!("{}: invalid JSON: {}", file_name, e),
                    "This wallet file is corrupted. Export the mnemonic (if possible) and recreate the wallet.",
                )
                .with_path(path)
                .with_code("ERR_FILE_MALFORMED"));
                continue;
            }
        };

        // Additional metadata validation
        if wallet.id.is_empty() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                "Wallet has empty ID",
                &format!("{}: wallet ID field is empty", file_name),
                "Recreate the wallet from the mnemonic.",
            )
            .with_path(path)
            .with_code("ERR_METADATA_INVALID"));
            corrupted_count += 1;
            continue;
        }

        if wallet.created_at.is_empty() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                "Wallet has empty created_at",
                &format!("{}: created_at field is empty", file_name),
                "Recreate the wallet from the mnemonic.",
            )
            .with_path(path)
            .with_code("ERR_METADATA_INVALID"));
            corrupted_count += 1;
            continue;
        }

        // Validate created_at is valid RFC3339
        if chrono::DateTime::parse_from_rfc3339(&wallet.created_at).is_err() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                "Wallet has invalid created_at",
                &format!("{}: created_at is not valid RFC3339: `{}`", file_name, wallet.created_at),
                "Recreate the wallet from the mnemonic.",
            )
            .with_path(path)
            .with_code("ERR_METADATA_INVALID"));
            corrupted_count += 1;
            continue;
        }

        valid_count += 1;
    }

    // Push summary finding
    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_WALLET_FILES,
            "Wallet files valid",
            &format!("All {} wallet file(s) are valid.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_WALLET_FILES,
            "Some wallet files corrupted",
            &format!(
                "{} of {} wallet file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Export valid wallets and recreate the corrupted ones.",
        )
        .with_code("WARN_ARTIFACTS_CORRUPTED"));
    }

    findings
}

// ---------------------------------------------------------------------------
// Key file inspection
// ---------------------------------------------------------------------------

/// Inspect all API key files in the vault.
///
/// Returns one finding per artifact, plus a summary finding.
pub fn check_key_files(vault_path: &Path) -> Vec<DoctorFinding> {
    let keys_dir = vault_path.join("keys");

    if !keys_dir.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_KEY_FILES,
            "No keys directory",
            "Keys directory does not exist; skipping key file inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&keys_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_KEY_FILES,
                "Cannot read keys directory",
                &format!("Keys directory exists but cannot be read: {}", e),
                "Check directory permissions.",
            )
            .with_path(keys_dir)
            .with_code("ERR_DIR_UNREADABLE")];
        }
    };

    let json_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    if json_entries.is_empty() {
        return vec![DoctorFinding::skipped(
            CHECK_KEY_FILES,
            "No API keys present",
            "No key files found in the keys directory.",
        )
        .with_path(keys_dir)];
    }

    let mut findings = Vec::new();
    let mut valid_count = 0;
    let mut corrupted_count = 0;

    for entry in json_entries {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_KEY_FILES,
                    "Key file unreadable",
                    &format!("{}: cannot read file: {}", file_name, e),
                    "Check file permissions.",
                )
                .with_path(path)
                .with_code("ERR_FILE_UNREADABLE"));
                continue;
            }
        };

        let _key_file: ApiKeyFile = match serde_json::from_str(&contents) {
            Ok(k) => k,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_KEY_FILES,
                    "Key file malformed",
                    &format!("{}: invalid JSON: {}", file_name, e),
                    "Delete and recreate the API key.",
                )
                .with_path(path)
                .with_code("ERR_FILE_MALFORMED"));
                continue;
            }
        };

        valid_count += 1;
    }

    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_KEY_FILES,
            "Key files valid",
            &format!("All {} key file(s) are valid.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_KEY_FILES,
            "Some key files corrupted",
            &format!(
                "{} of {} key file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Delete and recreate the corrupted API keys.",
        )
        .with_code("WARN_ARTIFACTS_CORRUPTED"));
    }

    findings
}

// ---------------------------------------------------------------------------
// Policy file inspection
// ---------------------------------------------------------------------------

/// Inspect all policy files in the vault.
///
/// Returns one finding per artifact, plus a summary finding.
pub fn check_policy_files(vault_path: &Path) -> Vec<DoctorFinding> {
    let policies_dir = vault_path.join("policies");

    if !policies_dir.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_POLICY_FILES,
            "No policies directory",
            "Policies directory does not exist; skipping policy file inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&policies_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_POLICY_FILES,
                "Cannot read policies directory",
                &format!("Policies directory exists but cannot be read: {}", e),
                "Check directory permissions.",
            )
            .with_path(policies_dir)
            .with_code("ERR_DIR_UNREADABLE")];
        }
    };

    let json_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    if json_entries.is_empty() {
        return vec![DoctorFinding::skipped(
            CHECK_POLICY_FILES,
            "No policies present",
            "No policy files found in the policies directory.",
        )
        .with_path(policies_dir)];
    }

    let mut findings = Vec::new();
    let mut valid_count = 0;
    let mut corrupted_count = 0;

    for entry in json_entries {
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();

        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_POLICY_FILES,
                    "Policy file unreadable",
                    &format!("{}: cannot read file: {}", file_name, e),
                    "Check file permissions.",
                )
                .with_path(path)
                .with_code("ERR_FILE_UNREADABLE"));
                continue;
            }
        };

        let _policy: Policy = match serde_json::from_str(&contents) {
            Ok(p) => p,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_POLICY_FILES,
                    "Policy file malformed",
                    &format!("{}: invalid JSON: {}", file_name, e),
                    "Delete and recreate the policy.",
                )
                .with_path(path)
                .with_code("ERR_FILE_MALFORMED"));
                continue;
            }
        };

        valid_count += 1;
    }

    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_POLICY_FILES,
            "Policy files valid",
            &format!("All {} policy file(s) are valid.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_POLICY_FILES,
            "Some policy files corrupted",
            &format!(
                "{} of {} policy file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Delete and recreate the corrupted policies.",
        )
        .with_code("WARN_ARTIFACTS_CORRUPTED"));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::doctor::DoctorStatus;
    use tempfile::TempDir;

    fn dummy_wallet(id: &str, name: &str) -> EncryptedWallet {
        EncryptedWallet::new(
            id.to_string(),
            name.to_string(),
            vec![],
            serde_json::json!({}),
            ows_core::KeyType::Mnemonic,
        )
    }

    fn dummy_key(id: &str, name: &str) -> ApiKeyFile {
        ApiKeyFile {
            id: id.to_string(),
            name: name.to_string(),
            token_hash: "deadbeef".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            wallet_ids: vec![],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: std::collections::HashMap::new(),
        }
    }

    fn dummy_policy(id: &str, name: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            rules: vec![],
            executable: None,
            config: None,
            action: ows_core::PolicyAction::Deny,
        }
    }

    // ---- Wallet tests ----

    #[test]
    fn test_wallet_files_skipped_when_dir_missing() {
        let temp = TempDir::new().unwrap();
        let findings = check_wallet_files(temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_wallet_files_empty_dir_is_warning() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir(vault.join("wallets")).ok();
        let findings = check_wallet_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Warning);
        assert_eq!(findings[0].code, Some("WARN_NO_WALLETS"));
    }

    #[test]
    fn test_wallet_files_one_valid() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        let wallet = dummy_wallet("wallet-1", "Test Wallet");
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(wallets_dir.join("wallet-1.json"), json).ok();

        let findings = check_wallet_files(&vault);
        // Should have 2 findings: one for the wallet, one summary
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok && f.detail.contains("1 wallet")));
        assert!(findings.iter().any(|f| f.id == CHECK_WALLET_FILES && f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_wallet_files_malformed_json() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        std::fs::write(wallets_dir.join("bad.json"), "{ invalid json }").ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Error && f.code == Some("ERR_FILE_MALFORMED")));
    }

    #[test]
    fn test_wallet_files_empty_id() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        let wallet = dummy_wallet("", "Empty ID Wallet");
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(wallets_dir.join("empty-id.json"), json).ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.code == Some("ERR_METADATA_INVALID")));
    }

    #[test]
    fn test_wallet_files_invalid_created_at() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        let wallet = EncryptedWallet::new(
            "test-id".to_string(),
            "Test".to_string(),
            vec![],
            serde_json::json!({}),
            ows_core::KeyType::Mnemonic,
        );
        // Override created_at to be invalid
        let mut json = serde_json::to_string_pretty(&wallet).unwrap();
        json = json.replace("2026-01-01T00:00:00Z", "not-a-date");
        std::fs::write(wallets_dir.join("bad-date.json"), json).ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.code == Some("ERR_METADATA_INVALID")));
    }

    #[test]
    fn test_wallet_files_mixed_valid_and_corrupt() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();

        // Valid wallet
        let wallet = dummy_wallet("good", "Good Wallet");
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        std::fs::write(wallets_dir.join("good.json"), json).ok();

        // Corrupted wallet
        std::fs::write(wallets_dir.join("bad.json"), "{ bad }").ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Error));
        assert!(findings.iter().any(|f| f.code == Some("WARN_ARTIFACTS_CORRUPTED")));
    }

    // ---- Key file tests ----

    #[test]
    fn test_key_files_skipped_when_dir_missing() {
        let temp = TempDir::new().unwrap();
        let findings = check_key_files(temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_key_files_empty_dir_is_skipped() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir(vault.join("keys")).ok();
        let findings = check_key_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_key_files_one_valid() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let keys_dir = vault.join("keys");
        std::fs::create_dir_all(&keys_dir).ok();
        let key = dummy_key("key-1", "Test Key");
        let json = serde_json::to_string_pretty(&key).unwrap();
        std::fs::write(keys_dir.join("key-1.json"), json).ok();

        let findings = check_key_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_key_files_malformed_json() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let keys_dir = vault.join("keys");
        std::fs::create_dir_all(&keys_dir).ok();
        std::fs::write(keys_dir.join("bad.json"), "{ invalid }").ok();

        let findings = check_key_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Error && f.code == Some("ERR_FILE_MALFORMED")));
    }

    // ---- Policy file tests ----

    #[test]
    fn test_policy_files_skipped_when_dir_missing() {
        let temp = TempDir::new().unwrap();
        let findings = check_policy_files(temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_policy_files_empty_dir_is_skipped() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir(vault.join("policies")).ok();
        let findings = check_policy_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
    }

    #[test]
    fn test_policy_files_one_valid() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let policies_dir = vault.join("policies");
        std::fs::create_dir_all(&policies_dir).ok();
        let policy = dummy_policy("pol-1", "Test Policy");
        let json = serde_json::to_string_pretty(&policy).unwrap();
        std::fs::write(policies_dir.join("pol-1.json"), json).ok();

        let findings = check_policy_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_policy_files_malformed_json() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let policies_dir = vault.join("policies");
        std::fs::create_dir_all(&policies_dir).ok();
        std::fs::write(policies_dir.join("bad.json"), "{ invalid }").ok();

        let findings = check_policy_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Error && f.code == Some("ERR_FILE_MALFORMED")));
    }
}
