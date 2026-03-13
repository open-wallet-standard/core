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
}
