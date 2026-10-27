use ows_core::{Policy, PolicyRule};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::OwsLibError;
use crate::vault;

fn is_valid_evm_address(address: &str) -> bool {
    address.len() == 42
        && address.starts_with("0x")
        && address[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn address_lists_mut(rules: &mut [PolicyRule]) -> impl Iterator<Item = &mut Vec<String>> {
    rules.iter_mut().filter_map(|rule| match rule {
        PolicyRule::RecipientAllowlist { addresses } => Some(addresses),
        PolicyRule::AllowedTypedDataContracts { contracts } => Some(contracts),
        _ => None,
    })
}

fn normalize_addresses(rules: &mut [PolicyRule]) {
    for addresses in address_lists_mut(rules) {
        for address in addresses {
            address.make_ascii_lowercase();
        }
    }
}

fn validate_addresses(rules: &[PolicyRule]) -> Result<(), OwsLibError> {
    for rule in rules {
        let (kind, addresses) = match rule {
            PolicyRule::RecipientAllowlist { addresses } => ("recipient_allowlist", addresses),
            PolicyRule::AllowedTypedDataContracts { contracts } => {
                ("allowed_typed_data_contracts", contracts)
            }
            _ => continue,
        };
        for address in addresses {
            if !is_valid_evm_address(address) {
                return Err(OwsLibError::InvalidInput(format!(
                    "malformed address in {kind}: {address}"
                )));
            }
        }
    }
    Ok(())
}

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
    validate_addresses(&policy.rules)?;
    let mut policy = policy.clone();
    normalize_addresses(&mut policy.rules);
    let dir = policies_dir(vault_path)?;
    let path = dir.join(format!("{}.json", policy.id));
    let json = serde_json::to_string_pretty(&policy)?;
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
    let mut policy: Policy = serde_json::from_str(&contents)?;
    normalize_addresses(&mut policy.rules);
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
                Ok(mut policy) => {
                    normalize_addresses(&mut policy.rules);
                    policies.push(policy);
                }
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

    #[test]
    fn recipient_addresses_are_validated_and_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let mut policy = test_policy("recipients", "Recipients");
        policy.rules = vec![PolicyRule::RecipientAllowlist {
            addresses: vec!["0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".into()],
        }];
        save_policy(&policy, Some(vault)).unwrap();
        let loaded = load_policy("recipients", Some(vault)).unwrap();
        assert_eq!(
            loaded.rules,
            vec![PolicyRule::RecipientAllowlist {
                addresses: vec!["0x742d35cc6634c0532925a3b844bc9e7595f2bd0c".into()]
            }]
        );

        if let PolicyRule::RecipientAllowlist { addresses } = &mut policy.rules[0] {
            addresses[0] = "0xdead".into();
        }
        assert!(save_policy(&policy, Some(vault))
            .unwrap_err()
            .to_string()
            .contains("malformed address"));
    }

    #[test]
    fn typed_data_contract_addresses_are_validated_and_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let mut policy = test_policy("contracts", "Contracts");
        policy.rules = vec![PolicyRule::AllowedTypedDataContracts {
            contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
        }];
        save_policy(&policy, Some(vault)).unwrap();
        let loaded = load_policy("contracts", Some(vault)).unwrap();
        assert_eq!(
            loaded.rules,
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022d473030f116ddee9f6b43ac78ba3".into()]
            }]
        );
    }
}
