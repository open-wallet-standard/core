use ows_core::ApiKeyFile;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::OwsLibError;
use crate::vault;

/// Token prefix that signals agent mode in the credential parameter.
pub const TOKEN_PREFIX: &str = "ows_key_";

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Returns the keys directory, creating it with strict permissions if needed.
fn keys_dir(vault_path: Option<&Path>) -> Result<PathBuf, OwsLibError> {
    let base = vault::resolve_vault_path(vault_path);
    let dir = base.join("keys");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&dir);
    Ok(dir)
}

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

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

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
fn set_file_permissions(_path: &Path) {}

// ---------------------------------------------------------------------------
// Token generation and hashing
// ---------------------------------------------------------------------------

/// Generate a random API token: `ows_key_<64 hex chars>` (256 bits of entropy).
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

/// SHA-256 hash of the raw token string, hex-encoded.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Save an API key file to `~/.ows/keys/<id>.json` with strict permissions.
pub fn save_api_key(key: &ApiKeyFile, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{}.json", key.id));
    let json = serde_json::to_string_pretty(key)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

/// Load an API key by its ID.
pub fn load_api_key(id: &str, vault_path: Option<&Path>) -> Result<ApiKeyFile, OwsLibError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound));
    }
    let contents = fs::read_to_string(&path)?;
    let key: ApiKeyFile = serde_json::from_str(&contents)?;
    Ok(key)
}

/// Look up an API key by the SHA-256 hash of the token.
/// Scans all key files — O(n) in the number of keys.
pub fn load_api_key_by_token_hash(
    token_hash: &str,
    vault_path: Option<&Path>,
) -> Result<ApiKeyFile, OwsLibError> {
    let keys = list_api_keys(vault_path)?;
    keys.into_iter()
        .find(|k| k.token_hash == token_hash)
        .ok_or(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound))
}

/// List all API keys, sorted by creation time (newest first).
pub fn list_api_keys(vault_path: Option<&Path>) -> Result<Vec<ApiKeyFile>, OwsLibError> {
    let dir = keys_dir(vault_path)?;
    let mut keys = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<ApiKeyFile>(&contents) {
                Ok(k) => keys.push(k),
                Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
            },
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }

    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys)
}

/// Delete an API key by ID.
pub fn delete_api_key(id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let dir = keys_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound));
    }
    fs::remove_file(&path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Store-aware API key CRUD
// ---------------------------------------------------------------------------

use ows_core::{store_set_indexed, store_remove_indexed, Store};

/// Save an API key via a Store.
pub fn save_api_key_with_store(
    key: &ApiKeyFile,
    store: &dyn Store,
) -> Result<(), OwsLibError> {
    let store_key = format!("keys/{}", key.id);
    let json = serde_json::to_string_pretty(key)?;
    store_set_indexed(store, &store_key, &json, "keys")?;
    Ok(())
}

/// Load an API key by ID via a Store.
pub fn load_api_key_with_store(
    id: &str,
    store: &dyn Store,
) -> Result<ApiKeyFile, OwsLibError> {
    let key = format!("keys/{id}");
    match store.get(&key)? {
        Some(json) => Ok(serde_json::from_str(&json)?),
        None => Err(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound)),
    }
}

/// Look up an API key by token hash via a Store.
pub fn load_api_key_by_token_hash_with_store(
    token_hash: &str,
    store: &dyn Store,
) -> Result<ApiKeyFile, OwsLibError> {
    let keys = list_api_keys_with_store(store)?;
    keys.into_iter()
        .find(|k| k.token_hash == token_hash)
        .ok_or(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound))
}

/// List all API keys via a Store, sorted by creation time (newest first).
pub fn list_api_keys_with_store(
    store: &dyn Store,
) -> Result<Vec<ApiKeyFile>, OwsLibError> {
    let store_keys = store.list("keys")?;
    let mut keys = Vec::new();

    for store_key in store_keys {
        if let Some(json) = store.get(&store_key)? {
            match serde_json::from_str::<ApiKeyFile>(&json) {
                Ok(k) => keys.push(k),
                Err(e) => eprintln!("warning: skipping {store_key}: {e}"),
            }
        }
    }

    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys)
}

/// Delete an API key by ID via a Store.
pub fn delete_api_key_with_store(
    id: &str,
    store: &dyn Store,
) -> Result<(), OwsLibError> {
    let key = format!("keys/{id}");
    if store.get(&key)?.is_none() {
        return Err(OwsLibError::Core(ows_core::OwsError::ApiKeyNotFound));
    }
    store_remove_indexed(store, &key, "keys")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_key(id: &str, name: &str, token: &str) -> ApiKeyFile {
        ApiKeyFile {
            id: id.to_string(),
            name: name.to_string(),
            token_hash: hash_token(token),
            created_at: "2026-03-22T10:30:00Z".to_string(),
            wallet_ids: vec!["wallet-1".to_string()],
            policy_ids: vec!["policy-1".to_string()],
            expires_at: None,
            wallet_secrets: HashMap::new(),
        }
    }

    #[test]
    fn generate_token_has_correct_format() {
        let token = generate_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        // 8 chars prefix + 64 hex chars = 72 total
        assert_eq!(token.len(), 72);
        // The hex part should be valid hex
        assert!(hex::decode(&token[TOKEN_PREFIX.len()..]).is_ok());
    }

    #[test]
    fn generate_token_is_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn hash_token_is_deterministic() {
        let token = "ows_key_abc123";
        assert_eq!(hash_token(token), hash_token(token));
    }

    #[test]
    fn hash_token_differs_for_different_tokens() {
        assert_ne!(hash_token("ows_key_abc"), hash_token("ows_key_def"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("key-1", "claude-agent", "ows_key_test");

        save_api_key(&key, Some(&vault)).unwrap();
        let loaded = load_api_key("key-1", Some(&vault)).unwrap();

        assert_eq!(loaded.id, "key-1");
        assert_eq!(loaded.name, "claude-agent");
        assert_eq!(loaded.token_hash, key.token_hash);
    }

    #[test]
    fn lookup_by_token_hash() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let token = "ows_key_findme";
        let key = test_key("key-2", "finder", token);

        save_api_key(&key, Some(&vault)).unwrap();

        let found = load_api_key_by_token_hash(&hash_token(token), Some(&vault)).unwrap();
        assert_eq!(found.id, "key-2");
    }

    #[test]
    fn lookup_nonexistent_hash_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_api_key_by_token_hash("nonexistent-hash", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_returns_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let mut k1 = test_key("k1", "first", "t1");
        k1.created_at = "2026-03-20T10:00:00Z".to_string();

        let mut k2 = test_key("k2", "second", "t2");
        k2.created_at = "2026-03-22T10:00:00Z".to_string();

        save_api_key(&k1, Some(&vault)).unwrap();
        save_api_key(&k2, Some(&vault)).unwrap();

        let keys = list_api_keys(Some(&vault)).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "k2"); // newest first
        assert_eq!(keys[1].id, "k1");
    }

    #[test]
    fn delete_removes_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("del-me", "delete", "token");

        save_api_key(&key, Some(&vault)).unwrap();
        assert_eq!(list_api_keys(Some(&vault)).unwrap().len(), 1);

        delete_api_key("del-me", Some(&vault)).unwrap();
        assert_eq!(list_api_keys(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_api_key("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_empty_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let keys = list_api_keys(Some(&vault)).unwrap();
        assert!(keys.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_has_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let key = test_key("perm-key", "perms", "token");

        save_api_key(&key, Some(&vault)).unwrap();

        let path = vault.join("keys/perm-key.json");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "key file should have 0600 permissions, got {:04o}",
            mode
        );

        let dir_mode = fs::metadata(vault.join("keys"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            dir_mode, 0o700,
            "keys dir should have 0700 permissions, got {:04o}",
            dir_mode
        );
    }

    // == Store-aware API key CRUD tests ==

    #[test]
    fn store_save_and_load_api_key() {
        let store = ows_core::InMemoryStore::new();
        let key = test_key("sk1", "store-key", "ows_key_test");

        save_api_key_with_store(&key, &store).unwrap();
        let loaded = load_api_key_with_store("sk1", &store).unwrap();
        assert_eq!(loaded.id, "sk1");
        assert_eq!(loaded.name, "store-key");
    }

    #[test]
    fn store_load_api_key_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = load_api_key_with_store("nonexistent", &store);
        assert!(result.is_err());
    }

    #[test]
    fn store_load_api_key_by_token_hash() {
        let store = ows_core::InMemoryStore::new();
        let token = "ows_key_findme";
        let key = test_key("sk2", "finder", token);

        save_api_key_with_store(&key, &store).unwrap();
        let found = load_api_key_by_token_hash_with_store(&hash_token(token), &store).unwrap();
        assert_eq!(found.id, "sk2");
    }

    #[test]
    fn store_list_api_keys_sorted() {
        let store = ows_core::InMemoryStore::new();

        let mut k1 = test_key("k1", "first", "t1");
        k1.created_at = "2026-03-20T10:00:00Z".to_string();

        let mut k2 = test_key("k2", "second", "t2");
        k2.created_at = "2026-03-22T10:00:00Z".to_string();

        save_api_key_with_store(&k1, &store).unwrap();
        save_api_key_with_store(&k2, &store).unwrap();

        let keys = list_api_keys_with_store(&store).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].id, "k2"); // newest first
        assert_eq!(keys[1].id, "k1");
    }

    #[test]
    fn store_delete_api_key() {
        let store = ows_core::InMemoryStore::new();
        let key = test_key("del-k", "delete-me", "token");

        save_api_key_with_store(&key, &store).unwrap();
        assert_eq!(list_api_keys_with_store(&store).unwrap().len(), 1);

        delete_api_key_with_store("del-k", &store).unwrap();
        assert_eq!(list_api_keys_with_store(&store).unwrap().len(), 0);
    }

    #[test]
    fn store_delete_api_key_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = delete_api_key_with_store("nonexistent", &store);
        assert!(result.is_err());
    }
}
