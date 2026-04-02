//! Read-only vault artifact inspection for `ows doctor`.

use std::fs;
use std::path::Path;

use ows_core::{ApiKeyFile, EncryptedWallet, Policy};

use crate::commands::doctor::report::{
    DoctorCheckId, DoctorFinding, OWS_DOCTOR_DIR_UNREADABLE,
    OWS_DOCTOR_KEY_FILE_INVALID, OWS_DOCTOR_KEY_FILE_UNREADABLE, OWS_DOCTOR_KEY_NONE,
    OWS_DOCTOR_KEY_SOME_CORRUPT, OWS_DOCTOR_POLICY_FILE_INVALID,
    OWS_DOCTOR_POLICY_FILE_UNREADABLE, OWS_DOCTOR_POLICY_NONE, OWS_DOCTOR_POLICY_SOME_CORRUPT,
    OWS_DOCTOR_WALLET_FILE_INVALID, OWS_DOCTOR_WALLET_FILE_UNREADABLE,
    OWS_DOCTOR_WALLET_METADATA_CORRUPT, OWS_DOCTOR_WALLET_NONE, OWS_DOCTOR_WALLET_SOME_CORRUPT,
};

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
pub fn check_wallet_files(vault_path: &Path) -> Vec<DoctorFinding> {
    let wallets_dir = vault_path.join("wallets");

    if !wallets_dir.exists() {
        return vec![DoctorFinding::skipped(
            CHECK_WALLET_FILES,
            OWS_DOCTOR_DIR_UNREADABLE,
            "No wallets directory",
            "Wallets directory does not exist; skipping wallet inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&wallets_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_WALLET_FILES,
                OWS_DOCTOR_DIR_UNREADABLE,
                "Cannot read wallets directory",
                &format!("Wallets directory exists but cannot be read: {}.", e),
                "Check directory permissions.",
            )
            .with_path(wallets_dir)];
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
            OWS_DOCTOR_WALLET_NONE,
            "No wallet files found",
            "The wallets directory exists but contains no wallet files.",
            "Run `ows wallet create` to create your first wallet.",
        )
        .with_path(wallets_dir)];
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
                    OWS_DOCTOR_WALLET_FILE_UNREADABLE,
                    "Wallet file cannot be read",
                    &format!("{}: I/O error reading file: {}.", file_name, e),
                    "Check file permissions with `ls -l ~/.ows/wallets/`.",
                )
                .with_path(path));
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
                    OWS_DOCTOR_WALLET_FILE_INVALID,
                    "Wallet file is not valid JSON",
                    &format!(
                        "{}: JSON parse error. This file is corrupted: {}.",
                        file_name, e
                    ),
                    "Export the mnemonic (if possible) and recreate the wallet with `ows wallet create`.",
                )
                .with_path(path));
                continue;
            }
        };

        // Additional metadata validation
        if wallet.id.is_empty() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                OWS_DOCTOR_WALLET_METADATA_CORRUPT,
                "Wallet has an empty ID field",
                &format!("{}: the wallet `id` field is empty.", file_name),
                "Export the mnemonic and recreate the wallet with `ows wallet create`.",
            )
            .with_path(path));
            corrupted_count += 1;
            continue;
        }

        if wallet.created_at.is_empty() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                OWS_DOCTOR_WALLET_METADATA_CORRUPT,
                "Wallet has an empty created_at field",
                &format!("{}: the `created_at` field is empty.", file_name),
                "Export the mnemonic and recreate the wallet with `ows wallet create`.",
            )
            .with_path(path));
            corrupted_count += 1;
            continue;
        }

        // Validate created_at is valid RFC3339
        if chrono::DateTime::parse_from_rfc3339(&wallet.created_at).is_err() {
            findings.push(DoctorFinding::error(
                CHECK_WALLET_FILES,
                OWS_DOCTOR_WALLET_METADATA_CORRUPT,
                "Wallet has an invalid created_at field",
                &format!(
                    "{}: `created_at` is not valid RFC3339: `{}`.",
                    file_name, wallet.created_at
                ),
                "Export the mnemonic and recreate the wallet with `ows wallet create`.",
            )
            .with_path(path));
            corrupted_count += 1;
            continue;
        }

        valid_count += 1;
    }

    // Summary finding
    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_WALLET_FILES,
            "All wallet files are valid",
            &format!("{} wallet file(s) parsed successfully.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_WALLET_FILES,
            OWS_DOCTOR_WALLET_SOME_CORRUPT,
            "Some wallet files are corrupted",
            &format!(
                "{} of {} wallet file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Export the mnemonic from any valid wallets and recreate the corrupted ones.",
        ));
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
            OWS_DOCTOR_DIR_UNREADABLE,
            "No keys directory",
            "Keys directory does not exist; skipping API key file inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&keys_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_KEY_FILES,
                OWS_DOCTOR_DIR_UNREADABLE,
                "Cannot read keys directory",
                &format!("Keys directory exists but cannot be read: {}.", e),
                "Check directory permissions.",
            )
            .with_path(keys_dir)];
        }
    };

    let json_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    if json_entries.is_empty() {
        return vec![DoctorFinding::skipped(
            CHECK_KEY_FILES,
            OWS_DOCTOR_KEY_NONE,
            "No API key files found",
            "The keys directory is empty.",
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
                    OWS_DOCTOR_KEY_FILE_UNREADABLE,
                    "API key file cannot be read",
                    &format!("{}: I/O error reading file: {}.", file_name, e),
                    "Check file permissions with `ls -l ~/.ows/keys/`.",
                )
                .with_path(path));
                continue;
            }
        };

        let _key_file: ApiKeyFile = match serde_json::from_str(&contents) {
            Ok(k) => k,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_KEY_FILES,
                    OWS_DOCTOR_KEY_FILE_INVALID,
                    "API key file is not valid JSON",
                    &format!("{}: JSON parse error. This file is corrupted: {}.", file_name, e),
                    "Delete and recreate the API key with `ows key revoke` then `ows key create`.",
                )
                .with_path(path));
                continue;
            }
        };

        valid_count += 1;
    }

    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_KEY_FILES,
            "All API key files are valid",
            &format!("{} API key file(s) parsed successfully.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_KEY_FILES,
            OWS_DOCTOR_KEY_SOME_CORRUPT,
            "Some API key files are corrupted",
            &format!(
                "{} of {} API key file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Delete and recreate the corrupted API keys.",
        ));
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
            OWS_DOCTOR_DIR_UNREADABLE,
            "No policies directory",
            "Policies directory does not exist; skipping policy file inspection.",
        )];
    }

    let entries: Vec<_> = match fs::read_dir(&policies_dir) {
        Ok(e) => e.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            return vec![DoctorFinding::error(
                CHECK_POLICY_FILES,
                OWS_DOCTOR_DIR_UNREADABLE,
                "Cannot read policies directory",
                &format!("Policies directory exists but cannot be read: {}.", e),
                "Check directory permissions.",
            )
            .with_path(policies_dir)];
        }
    };

    let json_entries: Vec<_> = entries
        .into_iter()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    if json_entries.is_empty() {
        return vec![DoctorFinding::skipped(
            CHECK_POLICY_FILES,
            OWS_DOCTOR_POLICY_NONE,
            "No policy files found",
            "The policies directory is empty.",
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
                    OWS_DOCTOR_POLICY_FILE_UNREADABLE,
                    "Policy file cannot be read",
                    &format!("{}: I/O error reading file: {}.", file_name, e),
                    "Check file permissions with `ls -l ~/.ows/policies/`.",
                )
                .with_path(path));
                continue;
            }
        };

        let _policy: Policy = match serde_json::from_str(&contents) {
            Ok(p) => p,
            Err(e) => {
                corrupted_count += 1;
                findings.push(DoctorFinding::error(
                    CHECK_POLICY_FILES,
                    OWS_DOCTOR_POLICY_FILE_INVALID,
                    "Policy file is not valid JSON",
                    &format!("{}: JSON parse error. This file is corrupted: {}.", file_name, e),
                    "Recreate the policy with `ows policy create`.",
                )
                .with_path(path));
                continue;
            }
        };

        valid_count += 1;
    }

    if corrupted_count == 0 {
        findings.push(DoctorFinding::ok(
            CHECK_POLICY_FILES,
            "All policy files are valid",
            &format!("{} policy file(s) parsed successfully.", valid_count),
        ));
    } else {
        findings.push(DoctorFinding::warning(
            CHECK_POLICY_FILES,
            OWS_DOCTOR_POLICY_SOME_CORRUPT,
            "Some policy files are corrupted",
            &format!(
                "{} of {} policy file(s) are corrupted.",
                corrupted_count,
                valid_count + corrupted_count
            ),
            "Recreate the corrupted policies.",
        ));
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
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_DIR_UNREADABLE));
    }

    #[test]
    fn test_wallet_files_empty_dir_is_warning() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir_all(vault.join("wallets")).ok();
        let findings = check_wallet_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Warning);
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_WALLET_NONE));
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
        assert!(findings
            .iter()
            .any(|f| f.status == DoctorStatus::Ok && f.detail.contains("1 wallet")));
        assert!(findings
            .iter()
            .any(|f| f.id == CHECK_WALLET_FILES && f.status == DoctorStatus::Ok));
    }

    #[test]
    fn test_wallet_files_malformed_json() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();
        std::fs::write(wallets_dir.join("bad.json"), "{ invalid json }").ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| {
            f.status == DoctorStatus::Error && f.code == Some(OWS_DOCTOR_WALLET_FILE_INVALID)
        }));
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
        assert!(findings
            .iter()
            .any(|f| f.code == Some(OWS_DOCTOR_WALLET_METADATA_CORRUPT)));
    }

    #[test]
    fn test_wallet_files_invalid_created_at() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        let wallets_dir = vault.join("wallets");
        std::fs::create_dir_all(&wallets_dir).ok();

        let bad_wallet_json = serde_json::json!({
            "ows_version": 2,
            "id": "test-id",
            "name": "Test",
            "created_at": "not-a-date",
            "accounts": [],
            "crypto": {},
            "key_type": "mnemonic"
        });
        std::fs::write(
            wallets_dir.join("bad-date.json"),
            serde_json::to_string_pretty(&bad_wallet_json).unwrap(),
        )
        .ok();

        let findings = check_wallet_files(&vault);
        assert!(findings
            .iter()
            .any(|f| f.code == Some(OWS_DOCTOR_WALLET_METADATA_CORRUPT)));
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

        // Corrupted wallet (malformed JSON)
        std::fs::write(wallets_dir.join("bad.json"), "{ bad }").ok();

        let findings = check_wallet_files(&vault);
        assert!(findings.iter().any(|f| f.status == DoctorStatus::Error));
        assert!(findings
            .iter()
            .any(|f| f.code == Some(OWS_DOCTOR_WALLET_SOME_CORRUPT)));
    }

    // ---- Key file tests ----

    #[test]
    fn test_key_files_skipped_when_dir_missing() {
        let temp = TempDir::new().unwrap();
        let findings = check_key_files(temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_DIR_UNREADABLE));
    }

    #[test]
    fn test_key_files_empty_dir_is_skipped() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir_all(vault.join("keys")).ok();
        let findings = check_key_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_KEY_NONE));
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
        assert!(findings.iter().any(|f| {
            f.status == DoctorStatus::Error && f.code == Some(OWS_DOCTOR_KEY_FILE_INVALID)
        }));
    }

    // ---- Policy file tests ----

    #[test]
    fn test_policy_files_skipped_when_dir_missing() {
        let temp = TempDir::new().unwrap();
        let findings = check_policy_files(temp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_DIR_UNREADABLE));
    }

    #[test]
    fn test_policy_files_empty_dir_is_skipped() {
        let temp = TempDir::new().unwrap();
        let vault = temp.path().join(".ows");
        std::fs::create_dir_all(vault.join("policies")).ok();
        let findings = check_policy_files(&vault);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, DoctorStatus::Skipped);
        assert_eq!(findings[0].code, Some(OWS_DOCTOR_POLICY_NONE));
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
        assert!(findings.iter().any(|f| {
            f.status == DoctorStatus::Error && f.code == Some(OWS_DOCTOR_POLICY_FILE_INVALID)
        }));
    }
}
