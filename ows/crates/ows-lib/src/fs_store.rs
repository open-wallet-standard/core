use ows_core::{Config, Store, StoreError};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// FsStore
// ---------------------------------------------------------------------------

/// Filesystem-backed Store implementation.
///
/// Maps keys like `wallets/{id}` to files at `{vault_path}/wallets/{id}.json`.
/// Applies strict UNIX permissions for sensitive namespaces (wallets, keys).
pub struct FsStore {
    vault_path: PathBuf,
}

impl FsStore {
    /// Create a new FsStore. If `vault_path` is `None`, uses the default `~/.ows`.
    pub fn new(vault_path: Option<&Path>) -> Self {
        Self {
            vault_path: vault_path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| Config::default().vault_path),
        }
    }

    /// Resolve a key to a filesystem path: `{vault_path}/{key}.json`.
    fn key_to_path(&self, key: &str) -> PathBuf {
        self.vault_path.join(format!("{key}.json"))
    }

    /// Returns true if the key is in a sensitive namespace (wallets, keys).
    fn is_sensitive(key: &str) -> bool {
        key.starts_with("wallets/") || key.starts_with("keys/")
    }
}

/// Set directory permissions to 0o700 (owner-only).
#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

/// Set file permissions to 0o600 (owner read/write only).
#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!(
            "warning: failed to set permissions on {}: {e}",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

impl Store for FsStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let path = self.key_to_path(key);
        match fs::read_to_string(&path) {
            Ok(contents) => Ok(Some(contents)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let path = self.key_to_path(key);

        // Create parent directories.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            if FsStore::is_sensitive(key) {
                set_dir_permissions(parent);
                // Also secure the vault root.
                set_dir_permissions(&self.vault_path);
            }
        }

        fs::write(&path, value)?;

        if FsStore::is_sensitive(key) {
            set_file_permissions(&path);
        }

        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        let path = self.key_to_path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Native directory listing — ignores the `_index` keys entirely.
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let dir = self.vault_path.join(prefix);

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };

        let mut keys = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    keys.push(format!("{prefix}/{stem}"));
                }
            }
        }

        Ok(keys)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (tempfile::TempDir, FsStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FsStore::new(Some(dir.path()));
        (dir, store)
    }

    // == Step 4: FsStore basic CRUD ==

    #[test]
    fn fs_get_missing_returns_none() {
        let (_dir, store) = test_store();
        assert_eq!(store.get("wallets/nonexistent").unwrap(), None);
    }

    #[test]
    fn fs_set_then_get_roundtrip() {
        let (_dir, store) = test_store();
        store.set("wallets/abc", r#"{"id":"abc"}"#).unwrap();
        assert_eq!(
            store.get("wallets/abc").unwrap(),
            Some(r#"{"id":"abc"}"#.to_string())
        );
    }

    #[test]
    fn fs_set_creates_parent_dirs() {
        let (dir, store) = test_store();
        store.set("wallets/abc", "test").unwrap();
        assert!(dir.path().join("wallets").exists());
    }

    #[test]
    fn fs_remove_deletes_file() {
        let (dir, store) = test_store();
        store.set("wallets/abc", "test").unwrap();
        assert!(dir.path().join("wallets/abc.json").exists());

        store.remove("wallets/abc").unwrap();
        assert!(!dir.path().join("wallets/abc.json").exists());
    }

    #[test]
    fn fs_remove_missing_is_ok() {
        let (_dir, store) = test_store();
        assert!(store.remove("wallets/nonexistent").is_ok());
    }

    #[test]
    fn fs_list_uses_readdir_not_index() {
        let (_dir, store) = test_store();
        // Write directly via set (no index helpers) — list should still find them.
        store.set("wallets/a", "1").unwrap();
        store.set("wallets/b", "2").unwrap();

        let mut keys = store.list("wallets").unwrap();
        keys.sort();
        assert_eq!(keys, vec!["wallets/a", "wallets/b"]);
    }

    #[test]
    fn fs_list_scoped_to_prefix() {
        let (_dir, store) = test_store();
        store.set("wallets/w1", "wallet").unwrap();
        store.set("keys/k1", "key").unwrap();
        store.set("policies/p1", "policy").unwrap();

        assert_eq!(store.list("wallets").unwrap(), vec!["wallets/w1"]);
        assert_eq!(store.list("keys").unwrap(), vec!["keys/k1"]);
        assert_eq!(store.list("policies").unwrap(), vec!["policies/p1"]);
    }

    #[test]
    fn fs_list_empty_dir_returns_empty() {
        let (_dir, store) = test_store();
        let keys = store.list("wallets").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn fs_list_ignores_non_json_files() {
        let (dir, store) = test_store();
        store.set("wallets/a", "1").unwrap();
        // Write a non-json file manually.
        std::fs::write(dir.path().join("wallets/readme.txt"), "ignore me").unwrap();

        let keys = store.list("wallets").unwrap();
        assert_eq!(keys, vec!["wallets/a"]);
    }

    #[cfg(unix)]
    #[test]
    fn fs_set_applies_0600_for_wallets_and_keys() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = test_store();
        store.set("wallets/w1", "secret").unwrap();
        store.set("keys/k1", "also-secret").unwrap();

        // Check file permissions.
        let w_mode = std::fs::metadata(dir.path().join("wallets/w1.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(w_mode, 0o600, "wallet file should be 0600, got {:04o}", w_mode);

        let k_mode = std::fs::metadata(dir.path().join("keys/k1.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(k_mode, 0o600, "key file should be 0600, got {:04o}", k_mode);

        // Check directory permissions.
        let wd_mode = std::fs::metadata(dir.path().join("wallets"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(wd_mode, 0o700, "wallets dir should be 0700, got {:04o}", wd_mode);
    }

    // == Step 5: Characterization tests — FsStore vs existing modules ==

    #[test]
    fn char_fs_store_reads_wallet_saved_by_vault_module() {
        use ows_core::{EncryptedWallet, KeyType, WalletAccount};

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-w1".to_string(),
            "char-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        // Save via the old vault module.
        crate::vault::save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Read via FsStore.
        let store = FsStore::new(Some(&vault));
        let json = store.get("wallets/char-w1").unwrap().expect("wallet not found via FsStore");
        let loaded: EncryptedWallet = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.id, wallet.id);
        assert_eq!(loaded.name, wallet.name);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].address, "0xabc");
    }

    #[test]
    fn char_vault_module_reads_wallet_saved_by_fs_store() {
        use ows_core::{EncryptedWallet, KeyType, WalletAccount};

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-w2".to_string(),
            "fs-store-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xdef".to_string(),
                address: "0xdef".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        // Save via FsStore.
        let store = FsStore::new(Some(&vault));
        let json = serde_json::to_string_pretty(&wallet).unwrap();
        store.set("wallets/char-w2", &json).unwrap();

        // Read via the old vault module.
        let loaded = crate::vault::load_wallet_by_name_or_id("char-w2", Some(&vault)).unwrap();
        assert_eq!(loaded.id, "char-w2");
        assert_eq!(loaded.name, "fs-store-wallet");
    }

    #[test]
    fn char_fs_store_reads_api_key_saved_by_key_store_module() {
        use ows_core::ApiKeyFile;
        use std::collections::HashMap;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let key = ApiKeyFile {
            id: "char-k1".to_string(),
            name: "char-key".to_string(),
            token_hash: "abc123hash".to_string(),
            created_at: "2026-03-22T10:00:00Z".to_string(),
            wallet_ids: vec!["w1".to_string()],
            policy_ids: vec![],
            expires_at: None,
            wallet_secrets: HashMap::new(),
        };

        // Save via old module.
        crate::key_store::save_api_key(&key, Some(&vault)).unwrap();

        // Read via FsStore.
        let store = FsStore::new(Some(&vault));
        let json = store.get("keys/char-k1").unwrap().expect("key not found via FsStore");
        let loaded: ApiKeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.id, "char-k1");
        assert_eq!(loaded.name, "char-key");
    }

    #[test]
    fn char_fs_store_reads_policy_saved_by_policy_store_module() {
        use ows_core::{Policy, PolicyAction, PolicyRule};

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let policy = Policy {
            id: "char-p1".to_string(),
            name: "Char Policy".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:1".to_string()],
            }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };

        // Save via old module.
        crate::policy_store::save_policy(&policy, Some(&vault)).unwrap();

        // Read via FsStore.
        let store = FsStore::new(Some(&vault));
        let json = store.get("policies/char-p1").unwrap().expect("policy not found via FsStore");
        let loaded: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.id, "char-p1");
        assert_eq!(loaded.name, "Char Policy");
    }

    #[test]
    fn char_fs_store_list_matches_vault_list() {
        use ows_core::{EncryptedWallet, KeyType};

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        // Save 3 wallets via old module.
        for i in 0..3 {
            let wallet = EncryptedWallet::new(
                format!("list-w{i}"),
                format!("wallet-{i}"),
                vec![],
                serde_json::json!({}),
                KeyType::Mnemonic,
            );
            crate::vault::save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        }

        // List via FsStore.
        let store = FsStore::new(Some(&vault));
        let mut fs_keys = store.list("wallets").unwrap();
        fs_keys.sort();

        // List via old module.
        let old_wallets = crate::vault::list_encrypted_wallets(Some(&vault)).unwrap();
        let mut old_ids: Vec<String> = old_wallets.iter().map(|w| format!("wallets/{}", w.id)).collect();
        old_ids.sort();

        assert_eq!(fs_keys, old_ids);
    }

    #[cfg(unix)]
    #[test]
    fn fs_set_no_strict_perms_for_policies() {
        use std::os::unix::fs::PermissionsExt;

        let (dir, store) = test_store();
        store.set("policies/p1", "not-secret").unwrap();

        let mode = std::fs::metadata(dir.path().join("policies/p1.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        // Should NOT be 0600 — policies are not sensitive.
        assert_ne!(mode, 0o600, "policy file should not have restricted permissions");
    }
}
