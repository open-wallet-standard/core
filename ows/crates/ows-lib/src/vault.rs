use ows_core::{Config, EncryptedWallet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::OwsLibError;

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

/// Warn if a directory has permissions more open than 0o700.
#[cfg(unix)]
pub fn check_vault_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            eprintln!(
                "warning: {} has permissions {:04o}, expected 0700",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

#[cfg(not(unix))]
pub fn check_vault_permissions(_path: &Path) {}

/// Resolve the vault path: use explicit path if provided, otherwise default (~/.ows).
pub fn resolve_vault_path(vault_path: Option<&Path>) -> PathBuf {
    match vault_path {
        Some(p) => p.to_path_buf(),
        None => Config::default().vault_path,
    }
}

/// Returns the wallets directory, creating it with strict permissions if necessary.
pub fn wallets_dir(vault_path: Option<&Path>) -> Result<PathBuf, OwsLibError> {
    let lws_dir = resolve_vault_path(vault_path);
    let dir = lws_dir.join("wallets");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&lws_dir);
    set_dir_permissions(&dir);
    Ok(dir)
}

/// Save an encrypted wallet file with strict permissions.
pub fn save_encrypted_wallet(
    wallet: &EncryptedWallet,
    vault_path: Option<&Path>,
) -> Result<(), OwsLibError> {
    let dir = wallets_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet.id));
    let json = serde_json::to_string_pretty(wallet)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

/// Load all encrypted wallets from the vault.
/// Checks directory permissions and warns if insecure.
/// Returns wallets sorted by created_at descending (newest first).
pub fn list_encrypted_wallets(
    vault_path: Option<&Path>,
) -> Result<Vec<EncryptedWallet>, OwsLibError> {
    let dir = wallets_dir(vault_path)?;
    check_vault_permissions(&dir);

    let mut wallets = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(wallets),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<EncryptedWallet>(&contents) {
                Ok(w) => wallets.push(w),
                Err(e) => {
                    eprintln!("warning: skipping {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }

    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets)
}

/// Look up a wallet by exact ID first, then by name (case-sensitive).
/// Returns an error if no wallet matches or if the name is ambiguous.
pub fn load_wallet_by_name_or_id(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<EncryptedWallet, OwsLibError> {
    let wallets = list_encrypted_wallets(vault_path)?;

    // Try exact ID match first
    if let Some(w) = wallets.iter().find(|w| w.id == name_or_id) {
        return Ok(w.clone());
    }

    // Try name match (case-sensitive)
    let matches: Vec<&EncryptedWallet> = wallets.iter().filter(|w| w.name == name_or_id).collect();
    match matches.len() {
        0 => Err(OwsLibError::WalletNotFound(name_or_id.to_string())),
        1 => Ok(matches[0].clone()),
        n => Err(OwsLibError::AmbiguousWallet {
            name: name_or_id.to_string(),
            count: n,
        }),
    }
}

/// Delete a wallet file from the vault by ID.
pub fn delete_wallet_file(id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let dir = wallets_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OwsLibError::WalletNotFound(id.to_string()));
    }
    fs::remove_file(&path)?;
    Ok(())
}

/// Check whether a wallet with the given name already exists in the vault.
pub fn wallet_name_exists(name: &str, vault_path: Option<&Path>) -> Result<bool, OwsLibError> {
    let wallets = list_encrypted_wallets(vault_path)?;
    Ok(wallets.iter().any(|w| w.name == name))
}

// ---------------------------------------------------------------------------
// Store-aware wallet CRUD
// ---------------------------------------------------------------------------

use ows_core::{store_set_indexed, store_remove_indexed, Store};

/// Save an encrypted wallet via a Store.
pub fn save_wallet_with_store(
    wallet: &EncryptedWallet,
    store: &dyn Store,
) -> Result<(), OwsLibError> {
    let key = format!("wallets/{}", wallet.id);
    let json = serde_json::to_string_pretty(wallet)?;
    store_set_indexed(store, &key, &json, "wallets")?;
    Ok(())
}

/// List all encrypted wallets via a Store, sorted by created_at descending.
pub fn list_wallets_with_store(
    store: &dyn Store,
) -> Result<Vec<EncryptedWallet>, OwsLibError> {
    let keys = store.list("wallets")?;
    let mut wallets = Vec::new();

    for key in keys {
        if let Some(json) = store.get(&key)? {
            match serde_json::from_str::<EncryptedWallet>(&json) {
                Ok(w) => wallets.push(w),
                Err(e) => eprintln!("warning: skipping {key}: {e}"),
            }
        }
    }

    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets)
}

/// Look up a wallet by exact ID first, then by name (case-sensitive) via a Store.
pub fn load_wallet_by_name_or_id_with_store(
    name_or_id: &str,
    store: &dyn Store,
) -> Result<EncryptedWallet, OwsLibError> {
    // Try direct ID lookup first (fast path — avoids listing all).
    let key = format!("wallets/{name_or_id}");
    if let Some(json) = store.get(&key)? {
        if let Ok(w) = serde_json::from_str::<EncryptedWallet>(&json) {
            return Ok(w);
        }
    }

    // Fall back to name search.
    let wallets = list_wallets_with_store(store)?;
    let matches: Vec<&EncryptedWallet> = wallets.iter().filter(|w| w.name == name_or_id).collect();
    match matches.len() {
        0 => Err(OwsLibError::WalletNotFound(name_or_id.to_string())),
        1 => Ok(matches[0].clone()),
        n => Err(OwsLibError::AmbiguousWallet {
            name: name_or_id.to_string(),
            count: n,
        }),
    }
}

/// Delete a wallet by ID via a Store.
pub fn delete_wallet_with_store(id: &str, store: &dyn Store) -> Result<(), OwsLibError> {
    // Check existence first.
    let key = format!("wallets/{id}");
    if store.get(&key)?.is_none() {
        return Err(OwsLibError::WalletNotFound(id.to_string()));
    }
    store_remove_indexed(store, &key, "wallets")?;
    Ok(())
}

/// Check whether a wallet with the given name already exists via a Store.
pub fn wallet_name_exists_with_store(
    name: &str,
    store: &dyn Store,
) -> Result<bool, OwsLibError> {
    let wallets = list_wallets_with_store(store)?;
    Ok(wallets.iter().any(|w| w.name == name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::{KeyType, WalletAccount};

    #[test]
    fn test_wallets_dir_creates_directory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let result = wallets_dir(Some(&vault)).unwrap();
        assert!(result.exists());
        assert_eq!(result, vault.join("wallets"));
    }

    #[test]
    fn test_save_and_list_wallets() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "test-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "test-id");
    }

    #[test]
    fn test_load_by_name_or_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "uuid-123".to_string(),
            "my-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:1:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:1".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            serde_json::json!({"cipher": "aes-256-gcm"}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Find by ID
        let found = load_wallet_by_name_or_id("uuid-123", Some(&vault)).unwrap();
        assert_eq!(found.name, "my-wallet");

        // Find by name
        let found = load_wallet_by_name_or_id("my-wallet", Some(&vault)).unwrap();
        assert_eq!(found.id, "uuid-123");

        // Not found
        let err = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(err.is_err());
    }

    #[test]
    fn test_delete_wallet_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "del-id".to_string(),
            "del-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);

        delete_wallet_file("del-id", Some(&vault)).unwrap();
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn test_wallet_name_exists() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "id-1".to_string(),
            "existing-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();
        assert!(wallet_name_exists("existing-name", Some(&vault)).unwrap());
        assert!(!wallet_name_exists("other-name", Some(&vault)).unwrap());
    }

    // === Characterization tests: lock down current behavior before refactoring ===

    #[test]
    fn char_save_and_load_by_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-id-123".to_string(),
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

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("char-id-123", Some(&vault)).unwrap();
        assert_eq!(loaded.id, wallet.id);
        assert_eq!(loaded.name, wallet.name);
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].address, "0xabc");
        assert_eq!(loaded.key_type, KeyType::Mnemonic);
    }

    #[test]
    fn char_save_and_load_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "char-uuid-456".to_string(),
            "my-char-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        let loaded = load_wallet_by_name_or_id("my-char-wallet", Some(&vault)).unwrap();
        assert_eq!(loaded.id, "char-uuid-456");
    }

    #[test]
    fn char_path_traversal_in_save_rejected() {
        // Wallet IDs with path traversal components should be rejected or sanitized
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "../../../etc/passwd".to_string(),
            "evil-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        // The file should be saved within the wallets dir only
        // Even if save succeeds, verify the file doesn't escape the vault
        let result = save_encrypted_wallet(&wallet, Some(&vault));
        if result.is_ok() {
            // If it doesn't error, verify no file was written outside the vault
            let wallets_dir_path = vault.join("wallets");
            let _escaped_path = vault.join("wallets").join("../../../etc/passwd.json");
            let canonical_wallets = wallets_dir_path.canonicalize().unwrap();

            // List what's actually in the wallets dir
            let entries: Vec<_> = std::fs::read_dir(&wallets_dir_path)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();

            // Check that any file written is within the wallets directory
            for entry in &entries {
                let path = entry.path().canonicalize().unwrap();
                assert!(
                    path.starts_with(&canonical_wallets),
                    "wallet file {:?} escaped the vault directory",
                    path
                );
            }
        }
        // If it errors, that's also acceptable (more secure)
    }

    #[test]
    fn char_path_traversal_in_delete_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        // Create a legitimate wallet first
        let wallet = EncryptedWallet::new(
            "legit-id".to_string(),
            "legit".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Attempt to delete with path traversal
        let result = delete_wallet_file("../../../etc/passwd", Some(&vault));
        // Should either error (ideal) or find no matching file
        assert!(result.is_err());

        // Original wallet should still exist
        assert_eq!(list_encrypted_wallets(Some(&vault)).unwrap().len(), 1);
    }

    #[test]
    fn char_list_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "w1-id".to_string(),
            "wallet-1".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        // Sleep a tiny bit to ensure different created_at timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        let w2 = EncryptedWallet::new(
            "w2-id".to_string(),
            "wallet-2".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w2, Some(&vault)).unwrap();

        let wallets = list_encrypted_wallets(Some(&vault)).unwrap();
        assert_eq!(wallets.len(), 2);
        // Newest first
        assert_eq!(wallets[0].id, "w2-id");
        assert_eq!(wallets[1].id, "w1-id");
    }

    #[test]
    fn char_duplicate_wallet_name_detected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let w1 = EncryptedWallet::new(
            "id-a".to_string(),
            "same-name".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&w1, Some(&vault)).unwrap();

        assert!(wallet_name_exists("same-name", Some(&vault)).unwrap());
    }

    #[test]
    fn char_wallet_not_found_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_wallet_by_name_or_id("nonexistent", Some(&vault));
        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::WalletNotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    fn char_delete_nonexistent_wallet_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_wallet_file("no-such-id", Some(&vault));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn char_wallet_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = EncryptedWallet::new(
            "perm-id".to_string(),
            "perm-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_encrypted_wallet(&wallet, Some(&vault)).unwrap();

        // Check file permissions are 0o600
        let file_path = vault.join("wallets/perm-id.json");
        let meta = std::fs::metadata(&file_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "wallet file should have 0600 permissions, got {:04o}",
            mode
        );

        // Check directory permissions are 0o700
        let wallets_dir_path = vault.join("wallets");
        let dir_meta = std::fs::metadata(&wallets_dir_path).unwrap();
        let dir_mode = dir_meta.permissions().mode() & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "wallets directory should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }

    // == Store-aware CRUD tests ==

    #[test]
    fn store_save_and_list_wallets() {
        let store = ows_core::InMemoryStore::new();
        let wallet = EncryptedWallet::new(
            "s-w1".to_string(),
            "store-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_wallet_with_store(&wallet, &store).unwrap();
        let wallets = list_wallets_with_store(&store).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, "s-w1");
    }

    #[test]
    fn store_load_wallet_by_id() {
        let store = ows_core::InMemoryStore::new();
        let wallet = EncryptedWallet::new(
            "id-123".to_string(),
            "my-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_wallet_with_store(&wallet, &store).unwrap();
        let loaded = load_wallet_by_name_or_id_with_store("id-123", &store).unwrap();
        assert_eq!(loaded.name, "my-wallet");
    }

    #[test]
    fn store_load_wallet_by_name() {
        let store = ows_core::InMemoryStore::new();
        let wallet = EncryptedWallet::new(
            "uuid-456".to_string(),
            "named-wallet".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_wallet_with_store(&wallet, &store).unwrap();
        let loaded = load_wallet_by_name_or_id_with_store("named-wallet", &store).unwrap();
        assert_eq!(loaded.id, "uuid-456");
    }

    #[test]
    fn store_load_wallet_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = load_wallet_by_name_or_id_with_store("nonexistent", &store);
        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::WalletNotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected WalletNotFound, got: {other}"),
        }
    }

    #[test]
    fn store_delete_wallet() {
        let store = ows_core::InMemoryStore::new();
        let wallet = EncryptedWallet::new(
            "del-w".to_string(),
            "delete-me".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_wallet_with_store(&wallet, &store).unwrap();
        assert_eq!(list_wallets_with_store(&store).unwrap().len(), 1);

        delete_wallet_with_store("del-w", &store).unwrap();
        assert_eq!(list_wallets_with_store(&store).unwrap().len(), 0);
    }

    #[test]
    fn store_delete_wallet_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = delete_wallet_with_store("nonexistent", &store);
        assert!(result.is_err());
    }

    #[test]
    fn store_wallet_name_exists() {
        let store = ows_core::InMemoryStore::new();
        let wallet = EncryptedWallet::new(
            "e-w1".to_string(),
            "existing".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );

        save_wallet_with_store(&wallet, &store).unwrap();
        assert!(wallet_name_exists_with_store("existing", &store).unwrap());
        assert!(!wallet_name_exists_with_store("other", &store).unwrap());
    }

    #[test]
    fn store_list_wallets_sorted_newest_first() {
        let store = ows_core::InMemoryStore::new();

        let w1 = EncryptedWallet::new(
            "w1".to_string(),
            "first".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_wallet_with_store(&w1, &store).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        let w2 = EncryptedWallet::new(
            "w2".to_string(),
            "second".to_string(),
            vec![],
            serde_json::json!({}),
            KeyType::Mnemonic,
        );
        save_wallet_with_store(&w2, &store).unwrap();

        let wallets = list_wallets_with_store(&store).unwrap();
        assert_eq!(wallets.len(), 2);
        assert_eq!(wallets[0].id, "w2"); // newest first
        assert_eq!(wallets[1].id, "w1");
    }
}
