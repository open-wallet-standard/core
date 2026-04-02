use std::path::PathBuf;

use ows_core::Config;

use crate::CliError;

/// Find the profile name nearest to the input (simple Levenshtein distance).
fn nearest_profile<'a>(input: &str, profiles: &'a [&str]) -> Option<&'a str> {
    profiles
        .iter()
        .min_by_key(|&p| edit_distance(input, p))
        .copied()
}

/// Compute Levenshtein distance between two strings (no external deps).
#[allow(clippy::needless_range_loop)]
fn edit_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    let mut matrix: Vec<Vec<usize>> = vec![vec![0; b_len + 1]; a_len + 1];
    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }
    for (i, ca) in a_chars.iter().enumerate() {
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                .min(matrix[i + 1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }
    matrix[a_len][b_len]
}

/// Show the active RPC profile and its endpoints, or a specific profile.
pub fn show(profile_name: Option<&str>) -> Result<(), CliError> {
    let config = Config::load_or_default();

    let name_to_show = profile_name.or(config.active_profile());

    if let Some(name) = name_to_show {
        let marker = if config.active_profile() == Some(name) {
            " (active)"
        } else {
            ""
        };
        if let Some(profile) = config.profile(name) {
            println!("Profile: {}{}", name, marker);
            println!();
            println!("Endpoints:");
            let mut endpoints: Vec<_> = profile.endpoints().collect();
            endpoints.sort_by_key(|(chain, _)| chain.to_string());
            for (chain, url) in endpoints {
                println!("  {:<45} {}", chain, url);
            }
        } else {
            return Err(CliError::InvalidArgs(format!(
                "profile '{}' not found",
                name
            )));
        }
    } else {
        println!("Active profile: (none)");
        println!();
        println!("No active profile set. Use 'ows rpc use <profile>' to activate a profile.");
    }

    Ok(())
}

/// List all configured RPC profiles.
pub fn list() -> Result<(), CliError> {
    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    if config
        .rpc_config
        .as_ref()
        .map(|c| c.profiles.is_empty())
        .unwrap_or(true)
    {
        println!("No RPC profiles configured.");
        println!("Add a profile with: ows rpc add <name> --chain <chain> --url <url>");
        return Ok(());
    }

    println!("RPC Profiles:");
    let mut names: Vec<_> = config.profile_names().collect();
    names.sort();
    for name in names {
        let marker = if config.active_profile() == Some(name) {
            " (active)"
        } else {
            ""
        };
        if let Some(profile) = config.profile(name) {
            println!("  {}{} ({} chains)", name, marker, profile.chains.len());
            let mut endpoints: Vec<_> = profile.endpoints().collect();
            endpoints.sort_by_key(|(chain, _)| chain.to_string());
            for (chain, url) in endpoints {
                println!("    {:<43} {}", chain, url);
            }
        }
    }

    println!();
    println!("Global RPC endpoints (fallback / when no profile is active):");

    let mut keys: Vec<&String> = config.rpc.keys().collect();
    keys.sort();
    for key in keys {
        let url = &config.rpc[key];
        let annotation = match defaults.get(key) {
            Some(default_url) if default_url == url => "(default)",
            Some(_) => "(custom)",
            None => "(custom)",
        };
        println!("  {:<40} {} {}", key, url, annotation);
    }

    Ok(())
}

/// Add or update RPC endpoint(s) in a profile.
pub fn add(name: &str, chains: &[String], urls: &[String]) -> Result<(), CliError> {
    if chains.len() != urls.len() {
        return Err(CliError::InvalidArgs(
            "number of --chain arguments must match --url arguments".into(),
        ));
    }

    if chains.is_empty() {
        return Err(CliError::InvalidArgs(
            "at least one --chain and --url pair is required".into(),
        ));
    }

    // Validate and normalize all chains first before making any changes
    let normalized_chains: Vec<String> = chains
        .iter()
        .map(|chain| {
            ows_core::parse_chain(chain)
                .map(|c| c.chain_id.to_string())
                .map_err(|e| CliError::InvalidArgs(format!("invalid chain '{}': {}", chain, e)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut config = Config::load_or_default();

    let is_new = config.profile(name).is_none();

    for (chain, url) in normalized_chains.iter().zip(urls.iter()) {
        config.upsert_profile_endpoint(name, chain, url.clone());
    }

    save_config(&config)?;

    if is_new {
        println!("Created new profile: {}", name);
    }
    for (chain, url) in normalized_chains.iter().zip(urls.iter()) {
        println!("Added {} -> {} in profile '{}'", chain, url, name);
    }

    if is_new {
        println!("Use `ows rpc use {}` to activate this profile.", name);
    }

    Ok(())
}

/// Remove (delete) an RPC profile.
pub fn remove(name: &str) -> Result<(), CliError> {
    let mut config = Config::load_or_default();

    if !config.profile_names().any(|n| n == name) {
        return Err(CliError::InvalidArgs(format!(
            "profile '{}' not found (available: {})",
            name,
            config.profile_names().collect::<Vec<_>>().join(", ")
        )));
    }

    let was_active = config.active_profile() == Some(name);
    config.delete_profile(name);
    save_config(&config)?;

    if was_active {
        println!("Removed profile '{}' (was active)", name);
    } else {
        println!("Removed profile '{}'", name);
    }
    Ok(())
}

/// Set the active RPC profile.
pub fn use_profile(name: &str) -> Result<(), CliError> {
    let mut config = Config::load_or_default();

    if !config.profile_names().any(|n| n == name) {
        let available: Vec<_> = config.profile_names().collect();
        let suggestion = nearest_profile(name, &available);
        let msg = if let Some(s) = suggestion {
            format!(
                "profile '{}' not found (available: {}). Did you mean '{}'?",
                name,
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.join(", ")
                },
                s
            )
        } else {
            format!(
                "profile '{}' not found (available: {})",
                name,
                if available.is_empty() {
                    "none".to_string()
                } else {
                    available.join(", ")
                }
            )
        };
        return Err(CliError::InvalidArgs(msg));
    }

    config.set_active_profile(Some(name.to_string()));
    save_config(&config)?;
    println!("Active profile set to '{}'", name);
    Ok(())
}

/// Clear the active RPC profile (use global/defaults only).
pub fn clear_active() -> Result<(), CliError> {
    let mut config = Config::load_or_default();

    if config.active_profile().is_none() {
        println!("No active profile to clear.");
        return Ok(());
    }

    config.set_active_profile(None);
    save_config(&config)?;
    println!("Active profile cleared (using global/default RPC endpoints)");
    Ok(())
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(&home).join(".ows/config.json")
}

fn save_config(config: &Config) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| CliError::InvalidArgs(format!("failed to serialize config: {}", e)))?;

    std::fs::write(config_path(), json)
        .map_err(|e| CliError::InvalidArgs(format!("failed to write config: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{edit_distance, nearest_profile};

    #[test]
    fn test_edit_distance() {
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("team-dev", "team-dev"), 0);
        assert_eq!(edit_distance("team-dev", "team-prod"), 4);
    }

    #[test]
    fn test_edit_distance_multibyte_utf8() {
        // Regression: edit_distance must count characters, not bytes.
        // 'é' is 2 bytes in UTF-8; a byte-oriented implementation would produce
        // wrong matrix dimensions and incorrect indices for multi-byte chars.
        assert_eq!(edit_distance("café", "cafe"), 1); // 'é'(2 bytes) vs 'e'(1 byte): cost 1
        assert_eq!(edit_distance("cafe", "café"), 1);
        assert_eq!(edit_distance("résumé", "resume"), 2); // 'é','é'(2 bytes each) -> 'e','e': cost 2
        assert_eq!(edit_distance("日本", "日本"), 0); // identical 6-byte strings
        assert_eq!(edit_distance("日本", "日韩"), 1); // different 3-byte chars: substitution cost 1
        assert_eq!(edit_distance("hello世界", "hello世界"), 0); // identical mixed ASCII/multibyte
        assert_eq!(edit_distance("hello世界", "hello世界!"), 1); // insertion at end
    }

    #[test]
    fn test_nearest_profile() {
        let profiles = vec!["team-dev", "mainnet-evm", "staging"];
        assert_eq!(nearest_profile("team-dev", &profiles), Some("team-dev"));
        assert_eq!(nearest_profile("team-prod", &profiles), Some("team-dev")); // 4 vs 6 vs 7
        assert_eq!(nearest_profile("staging", &profiles), Some("staging"));
        assert_eq!(nearest_profile("mainnet", &profiles), Some("mainnet-evm"));
        // Verify the result has the minimum edit distance
        let result = nearest_profile("nonexistent", &profiles);
        assert!(result.is_some());
        let min_dist = profiles
            .iter()
            .map(|p| edit_distance("nonexistent", p))
            .min()
            .unwrap();
        assert_eq!(edit_distance("nonexistent", result.unwrap()), min_dist);
        assert_eq!(nearest_profile("", &profiles), Some("staging")); // 5 vs 9 vs 8
    }
}
