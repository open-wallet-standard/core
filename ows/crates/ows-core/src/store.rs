use std::collections::HashMap;
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// StoreError
// ---------------------------------------------------------------------------

/// A concrete, object-safe error type for Store implementations.
#[derive(Debug)]
pub struct StoreError(pub Box<dyn std::error::Error + Send + Sync>);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError(Box::new(e))
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError(Box::new(e))
    }
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

/// Minimal key-value storage backend for OWS.
///
/// The library owns the key namespace (`wallets/{id}`, `keys/{id}`,
/// `policies/{id}`) and serialization. Implementations just move strings
/// by key.
///
/// # List behaviour
///
/// The default `list` implementation reads an internal index key
/// (`_index/{prefix}`) maintained by the library's index helpers.
/// Backends with native prefix scanning (filesystem, databases) should
/// override `list` for better performance.
pub trait Store: Send + Sync {
    /// Get a value by key. Returns `Ok(None)` if not found.
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Set a value by key, creating or overwriting.
    fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Remove a value by key. Returns `Ok(())` even if the key didn't exist.
    fn remove(&self, key: &str) -> Result<(), StoreError>;

    /// List all keys under a prefix (e.g. `"wallets"`).
    ///
    /// Returns full keys like `["wallets/abc", "wallets/def"]`.
    ///
    /// The default implementation reads the `_index/{prefix}` key maintained
    /// by [`store_set_indexed`] / [`store_remove_indexed`]. Override this if
    /// your backend supports native prefix enumeration.
    fn list(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        let index_key = format!("_index/{prefix}");
        match self.get(&index_key)? {
            Some(json) => {
                let keys: Vec<String> = serde_json::from_str(&json)?;
                Ok(keys)
            }
            None => Ok(vec![]),
        }
    }
}

// ---------------------------------------------------------------------------
// Index helpers
// ---------------------------------------------------------------------------

/// Set a value and update the internal index for the given prefix.
///
/// Calls `store.set(key, value)` then appends `key` to `_index/{prefix}`
/// (if not already present). Backends that override `list` with native
/// enumeration can ignore the index — it is harmless but unused.
pub fn store_set_indexed(
    store: &dyn Store,
    key: &str,
    value: &str,
    prefix: &str,
) -> Result<(), StoreError> {
    store.set(key, value)?;

    let index_key = format!("_index/{prefix}");
    let mut keys: Vec<String> = match store.get(&index_key)? {
        Some(json) => serde_json::from_str(&json)?,
        None => vec![],
    };

    let key_str = key.to_string();
    if !keys.contains(&key_str) {
        keys.push(key_str);
        let json = serde_json::to_string(&keys)?;
        store.set(&index_key, &json)?;
    }

    Ok(())
}

/// Remove a value and update the internal index for the given prefix.
///
/// Calls `store.remove(key)` then removes `key` from `_index/{prefix}`.
pub fn store_remove_indexed(
    store: &dyn Store,
    key: &str,
    prefix: &str,
) -> Result<(), StoreError> {
    store.remove(key)?;

    let index_key = format!("_index/{prefix}");
    if let Some(json) = store.get(&index_key)? {
        let mut keys: Vec<String> = serde_json::from_str(&json)?;
        keys.retain(|k| k != key);
        let json = serde_json::to_string(&keys)?;
        store.set(&index_key, &json)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// InMemoryStore
// ---------------------------------------------------------------------------

/// In-memory Store implementation for testing.
///
/// Uses the default `list` implementation (index-based), so it exercises
/// the full index helper path.
pub struct InMemoryStore {
    data: RwLock<HashMap<String, String>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Store for InMemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        let data = self.data.read().map_err(|e| StoreError(e.to_string().into()))?;
        Ok(data.get(key).cloned())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let mut data = self.data.write().map_err(|e| StoreError(e.to_string().into()))?;
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        let mut data = self.data.write().map_err(|e| StoreError(e.to_string().into()))?;
        data.remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // == Step 1: Store trait ==

    #[test]
    fn store_is_object_safe() {
        // This compiles only if Store is object-safe.
        fn assert_object_safe(_: &dyn Store) {}
        let store = InMemoryStore::new();
        assert_object_safe(&store);
    }

    #[test]
    fn default_list_returns_empty_when_no_index() {
        let store = InMemoryStore::new();
        let result = store.list("wallets").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn default_list_reads_index_key() {
        let store = InMemoryStore::new();
        let index = serde_json::to_string(&vec!["wallets/a", "wallets/b"]).unwrap();
        store.set("_index/wallets", &index).unwrap();

        let result = store.list("wallets").unwrap();
        assert_eq!(result, vec!["wallets/a", "wallets/b"]);
    }

    // == Step 2: InMemoryStore ==

    #[test]
    fn get_missing_returns_none() {
        let store = InMemoryStore::new();
        assert_eq!(store.get("nonexistent").unwrap(), None);
    }

    #[test]
    fn set_then_get_roundtrip() {
        let store = InMemoryStore::new();
        store.set("key", "value").unwrap();
        assert_eq!(store.get("key").unwrap(), Some("value".to_string()));
    }

    #[test]
    fn set_overwrites_existing() {
        let store = InMemoryStore::new();
        store.set("key", "v1").unwrap();
        store.set("key", "v2").unwrap();
        assert_eq!(store.get("key").unwrap(), Some("v2".to_string()));
    }

    #[test]
    fn remove_deletes_key() {
        let store = InMemoryStore::new();
        store.set("key", "value").unwrap();
        store.remove("key").unwrap();
        assert_eq!(store.get("key").unwrap(), None);
    }

    #[test]
    fn remove_missing_is_ok() {
        let store = InMemoryStore::new();
        assert!(store.remove("nonexistent").is_ok());
    }

    // == Step 3: Index helpers ==

    #[test]
    fn set_indexed_writes_value_and_updates_index() {
        let store = InMemoryStore::new();
        store_set_indexed(&store, "wallets/abc", r#"{"id":"abc"}"#, "wallets").unwrap();

        // Value is stored
        assert_eq!(
            store.get("wallets/abc").unwrap(),
            Some(r#"{"id":"abc"}"#.to_string())
        );

        // Index is updated
        let keys = store.list("wallets").unwrap();
        assert_eq!(keys, vec!["wallets/abc"]);
    }

    #[test]
    fn set_indexed_is_idempotent() {
        let store = InMemoryStore::new();
        store_set_indexed(&store, "wallets/abc", r#"{"v":1}"#, "wallets").unwrap();
        store_set_indexed(&store, "wallets/abc", r#"{"v":2}"#, "wallets").unwrap();

        // Value is updated
        assert_eq!(
            store.get("wallets/abc").unwrap(),
            Some(r#"{"v":2}"#.to_string())
        );

        // Index has only one entry (no duplicates)
        let keys = store.list("wallets").unwrap();
        assert_eq!(keys, vec!["wallets/abc"]);
    }

    #[test]
    fn remove_indexed_removes_from_index() {
        let store = InMemoryStore::new();
        store_set_indexed(&store, "wallets/a", "v1", "wallets").unwrap();
        store_set_indexed(&store, "wallets/b", "v2", "wallets").unwrap();

        store_remove_indexed(&store, "wallets/a", "wallets").unwrap();

        // Value is gone
        assert_eq!(store.get("wallets/a").unwrap(), None);

        // Index reflects removal
        let keys = store.list("wallets").unwrap();
        assert_eq!(keys, vec!["wallets/b"]);
    }

    #[test]
    fn remove_indexed_noop_when_absent() {
        let store = InMemoryStore::new();
        // No index exists at all — should not error
        assert!(store_remove_indexed(&store, "wallets/x", "wallets").is_ok());
    }

    #[test]
    fn list_returns_correct_keys_after_mutations() {
        let store = InMemoryStore::new();
        store_set_indexed(&store, "wallets/a", "1", "wallets").unwrap();
        store_set_indexed(&store, "wallets/b", "2", "wallets").unwrap();
        store_set_indexed(&store, "wallets/c", "3", "wallets").unwrap();
        store_remove_indexed(&store, "wallets/b", "wallets").unwrap();

        let keys = store.list("wallets").unwrap();
        assert_eq!(keys, vec!["wallets/a", "wallets/c"]);
    }

    #[test]
    fn separate_prefixes_are_independent() {
        let store = InMemoryStore::new();
        store_set_indexed(&store, "wallets/w1", "wallet", "wallets").unwrap();
        store_set_indexed(&store, "keys/k1", "key", "keys").unwrap();
        store_set_indexed(&store, "policies/p1", "policy", "policies").unwrap();

        assert_eq!(store.list("wallets").unwrap(), vec!["wallets/w1"]);
        assert_eq!(store.list("keys").unwrap(), vec!["keys/k1"]);
        assert_eq!(store.list("policies").unwrap(), vec!["policies/p1"]);
    }
}
