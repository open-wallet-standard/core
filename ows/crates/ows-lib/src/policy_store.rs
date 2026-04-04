use ows_core::Policy;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::OwsLibError;
use crate::vault;

/// Returns the policies directory, creating it if needed.
/// Policies are not secret — no restrictive permissions applied.
pub fn policies_dir(vault_path: Option<&Path>) -> Result<PathBuf, OwsLibError> {
    let base = vault::resolve_vault_path(vault_path);
    let dir = base.join("policies");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Save a policy to `~/.ows/policies/<id>.json`.
pub fn save_policy(policy: &Policy, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{}.json", policy.id));
    let json = serde_json::to_string_pretty(policy)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Load a single policy by ID.
pub fn load_policy(id: &str, vault_path: Option<&Path>) -> Result<Policy, OwsLibError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OwsLibError::InvalidInput(format!("policy not found: {id}")));
    }
    let contents = fs::read_to_string(&path)?;
    let policy: Policy = serde_json::from_str(&contents)?;
    Ok(policy)
}

/// List all policies, sorted alphabetically by name.
pub fn list_policies(vault_path: Option<&Path>) -> Result<Vec<Policy>, OwsLibError> {
    let dir = policies_dir(vault_path)?;
    let mut policies = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(policies),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<Policy>(&contents) {
                Ok(p) => policies.push(p),
                Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
            },
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }

    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}

/// Delete a policy by ID.
pub fn delete_policy(id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(OwsLibError::InvalidInput(format!("policy not found: {id}")));
    }
    fs::remove_file(&path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Store-aware policy CRUD
// ---------------------------------------------------------------------------

use ows_core::{store_set_indexed, store_remove_indexed, Store};

/// Save a policy via a Store.
pub fn save_policy_with_store(
    policy: &Policy,
    store: &dyn Store,
) -> Result<(), OwsLibError> {
    let key = format!("policies/{}", policy.id);
    let json = serde_json::to_string_pretty(policy)?;
    store_set_indexed(store, &key, &json, "policies")?;
    Ok(())
}

/// Load a policy by ID via a Store.
pub fn load_policy_with_store(
    id: &str,
    store: &dyn Store,
) -> Result<Policy, OwsLibError> {
    let key = format!("policies/{id}");
    match store.get(&key)? {
        Some(json) => Ok(serde_json::from_str(&json)?),
        None => Err(OwsLibError::InvalidInput(format!("policy not found: {id}"))),
    }
}

/// List all policies via a Store, sorted alphabetically by name.
pub fn list_policies_with_store(
    store: &dyn Store,
) -> Result<Vec<Policy>, OwsLibError> {
    let store_keys = store.list("policies")?;
    let mut policies = Vec::new();

    for store_key in store_keys {
        if let Some(json) = store.get(&store_key)? {
            match serde_json::from_str::<Policy>(&json) {
                Ok(p) => policies.push(p),
                Err(e) => eprintln!("warning: skipping {store_key}: {e}"),
            }
        }
    }

    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}

/// Delete a policy by ID via a Store.
pub fn delete_policy_with_store(
    id: &str,
    store: &dyn Store,
) -> Result<(), OwsLibError> {
    let key = format!("policies/{id}");
    if store.get(&key)?.is_none() {
        return Err(OwsLibError::InvalidInput(format!("policy not found: {id}")));
    }
    store_remove_indexed(store, &key, "policies")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::{PolicyAction, PolicyRule};

    fn test_policy(id: &str, name: &str) -> Policy {
        Policy {
            id: id.to_string(),
            name: name.to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".to_string()],
            }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let policy = test_policy("base-only", "Base Only");

        save_policy(&policy, Some(&vault)).unwrap();
        let loaded = load_policy("base-only", Some(&vault)).unwrap();

        assert_eq!(loaded.id, "base-only");
        assert_eq!(loaded.name, "Base Only");
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn list_returns_sorted_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        save_policy(&test_policy("z-policy", "Zebra"), Some(&vault)).unwrap();
        save_policy(&test_policy("a-policy", "Alpha"), Some(&vault)).unwrap();
        save_policy(&test_policy("m-policy", "Middle"), Some(&vault)).unwrap();

        let policies = list_policies(Some(&vault)).unwrap();
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].name, "Alpha");
        assert_eq!(policies[1].name, "Middle");
        assert_eq!(policies[2].name, "Zebra");
    }

    #[test]
    fn delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        save_policy(&test_policy("del-me", "Delete Me"), Some(&vault)).unwrap();
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 1);

        delete_policy("del-me", Some(&vault)).unwrap();
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 0);
    }

    #[test]
    fn load_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = load_policy("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn delete_nonexistent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let result = delete_policy("nope", Some(&vault));
        assert!(result.is_err());
    }

    #[test]
    fn list_empty_vault_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let policies = list_policies(Some(&vault)).unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn save_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let mut policy = test_policy("overwrite-me", "Version 1");
        save_policy(&policy, Some(&vault)).unwrap();

        policy.name = "Version 2".to_string();
        policy.version = 2;
        save_policy(&policy, Some(&vault)).unwrap();

        let loaded = load_policy("overwrite-me", Some(&vault)).unwrap();
        assert_eq!(loaded.name, "Version 2");
        assert_eq!(loaded.version, 2);
        assert_eq!(list_policies(Some(&vault)).unwrap().len(), 1);
    }

    #[test]
    fn policy_with_executable_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let policy = Policy {
            id: "sim-policy".to_string(),
            name: "Simulation".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![],
            executable: Some("/usr/local/bin/simulate-tx".to_string()),
            config: Some(serde_json::json!({"rpc": "https://mainnet.base.org"})),
            action: PolicyAction::Deny,
        };

        save_policy(&policy, Some(&vault)).unwrap();
        let loaded = load_policy("sim-policy", Some(&vault)).unwrap();
        assert_eq!(loaded.executable.unwrap(), "/usr/local/bin/simulate-tx");
        assert!(loaded.config.is_some());
    }

    // == Store-aware policy CRUD tests ==

    #[test]
    fn store_save_and_load_policy() {
        let store = ows_core::InMemoryStore::new();
        let policy = test_policy("sp1", "Store Policy");

        save_policy_with_store(&policy, &store).unwrap();
        let loaded = load_policy_with_store("sp1", &store).unwrap();
        assert_eq!(loaded.id, "sp1");
        assert_eq!(loaded.name, "Store Policy");
    }

    #[test]
    fn store_load_policy_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = load_policy_with_store("nonexistent", &store);
        assert!(result.is_err());
    }

    #[test]
    fn store_list_policies_sorted_by_name() {
        let store = ows_core::InMemoryStore::new();

        save_policy_with_store(&test_policy("z-p", "Zebra"), &store).unwrap();
        save_policy_with_store(&test_policy("a-p", "Alpha"), &store).unwrap();
        save_policy_with_store(&test_policy("m-p", "Middle"), &store).unwrap();

        let policies = list_policies_with_store(&store).unwrap();
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].name, "Alpha");
        assert_eq!(policies[1].name, "Middle");
        assert_eq!(policies[2].name, "Zebra");
    }

    #[test]
    fn store_delete_policy() {
        let store = ows_core::InMemoryStore::new();

        save_policy_with_store(&test_policy("del-p", "Delete Me"), &store).unwrap();
        assert_eq!(list_policies_with_store(&store).unwrap().len(), 1);

        delete_policy_with_store("del-p", &store).unwrap();
        assert_eq!(list_policies_with_store(&store).unwrap().len(), 0);
    }

    #[test]
    fn store_delete_policy_not_found() {
        let store = ows_core::InMemoryStore::new();
        let result = delete_policy_with_store("nonexistent", &store);
        assert!(result.is_err());
    }
}
