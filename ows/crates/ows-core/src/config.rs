use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Backup configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_backup: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_backups: Option<u32>,
}

/// RPC endpoint configuration for a single chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEndpoint {
    pub url: String,
}

/// Named RPC profile containing chain-specific endpoint overrides.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcProfile {
    #[serde(default)]
    pub chains: HashMap<String, ChainEndpoint>,
}

impl RpcProfile {
    /// Returns the URL for a chain if defined in this profile.
    pub fn endpoint(&self, chain: &str) -> Option<&str> {
        self.chains.get(chain).map(|e| e.url.as_str())
    }

    /// Returns an iterator over all chain endpoints.
    pub fn endpoints(&self) -> impl Iterator<Item = (&str, &str)> {
        self.chains
            .iter()
            .map(|(k, v)| (k.as_str(), v.url.as_str()))
    }
}

/// RPC configuration with profile support.
///
/// Supports two formats for backward compatibility:
/// - Legacy: `rpc: { "eip155:1": "https://..." }` (flat, at root level)
/// - Current: `rpc_config: { "activeProfile": "dev", "profiles": { "dev": { "chains": { "eip155:1": { "url": "https://..." } } } } }`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RpcConfig {
    /// Currently active profile name.
    #[serde(rename = "activeProfile", skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
    /// Named RPC profiles.
    #[serde(default)]
    pub profiles: HashMap<String, RpcProfile>,
}

fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".ows")
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_vault_path")]
    pub vault_path: PathBuf,
    /// Legacy flat RPC endpoints (chain_id -> url). Used for backward compatibility.
    /// Empty by default when loading from disk — built-in defaults come from
    /// `Config::default_rpc()` at runtime and are not persisted.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub rpc: HashMap<String, String>,
    /// New structured RPC config with profile support.
    /// When present, takes precedence over legacy `rpc` field for profile lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_config: Option<RpcConfig>,
    #[serde(default)]
    pub plugins: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupConfig>,
}

impl Config {
    /// Returns the built-in default RPC endpoints for well-known chains.
    pub fn default_rpc() -> HashMap<String, String> {
        let mut rpc = HashMap::new();
        rpc.insert("eip155:1".into(), "https://eth.llamarpc.com".into());
        rpc.insert("eip155:137".into(), "https://polygon-rpc.com".into());
        rpc.insert("eip155:42161".into(), "https://arb1.arbitrum.io/rpc".into());
        rpc.insert("eip155:10".into(), "https://mainnet.optimism.io".into());
        rpc.insert("eip155:8453".into(), "https://mainnet.base.org".into());
        rpc.insert("eip155:9745".into(), "https://rpc.plasma.to".into());
        rpc.insert(
            "eip155:56".into(),
            "https://bsc-dataseed.binance.org".into(),
        );
        rpc.insert(
            "eip155:43114".into(),
            "https://api.avax.network/ext/bc/C/rpc".into(),
        );
        rpc.insert(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            "https://api.mainnet-beta.solana.com".into(),
        );
        rpc.insert(
            "bip122:000000000019d6689c085ae165831e93".into(),
            "https://mempool.space/api".into(),
        );
        rpc.insert(
            "cosmos:cosmoshub-4".into(),
            "https://cosmos-rest.publicnode.com".into(),
        );
        rpc.insert("tron:mainnet".into(), "https://api.trongrid.io".into());
        rpc.insert("ton:mainnet".into(), "https://toncenter.com/api/v2".into());
        rpc.insert(
            "fil:mainnet".into(),
            "https://api.node.glif.io/rpc/v1".into(),
        );
        rpc.insert(
            "sui:mainnet".into(),
            "https://fullnode.mainnet.sui.io:443".into(),
        );
        rpc.insert("xrpl:mainnet".into(), "https://s1.ripple.com:51234".into());
        rpc.insert(
            "xrpl:testnet".into(),
            "https://s.altnet.rippletest.net:51234".into(),
        );
        rpc.insert(
            "xrpl:devnet".into(),
            "https://s.devnet.rippletest.net:51234".into(),
        );
        rpc
    }
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Config {
            vault_path: PathBuf::from(home).join(".ows"),
            rpc: Self::default_rpc(),
            rpc_config: None,
            plugins: HashMap::new(),
            backup: None,
        }
    }
}

impl Config {
    /// Look up an RPC URL by chain identifier.
    /// Checks: user-defined global rpc > built-in defaults.
    pub fn rpc_url(&self, chain: &str) -> Option<String> {
        self.rpc
            .get(chain)
            .cloned()
            .or_else(|| Config::default_rpc().get(chain).cloned())
    }

    /// Returns the name of the active profile, if any.
    pub fn active_profile(&self) -> Option<&str> {
        self.rpc_config.as_ref()?.active_profile.as_deref()
    }

    /// Returns all profile names.
    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.rpc_config
            .as_ref()
            .map(|c| c.profiles.keys().map(|k| k.as_str()))
            .into_iter()
            .flatten()
    }

    /// Get a profile by name.
    pub fn profile(&self, name: &str) -> Option<&RpcProfile> {
        self.rpc_config.as_ref()?.profiles.get(name)
    }

    /// Look up an RPC URL from the active profile.
    pub fn profile_rpc_url(&self, chain: &str) -> Option<&str> {
        let profile_name = self.active_profile()?;
        let profile = self.profile(profile_name)?;
        profile.endpoint(chain)
    }

    /// Resolve RPC URL with precedence: explicit > active profile > global rpc > defaults.
    pub fn resolve_rpc_url(&self, chain: &str, explicit: Option<&str>) -> Option<String> {
        if let Some(url) = explicit {
            return Some(url.to_string());
        }
        if let Some(url) = self.profile_rpc_url(chain) {
            return Some(url.to_string());
        }
        if let Some(url) = self.rpc_url(chain) {
            return Some(url.to_string());
        }
        Config::default_rpc().get(chain).map(|s| s.to_string())
    }

    /// Returns the structured RPC config, creating a default one if not present.
    pub fn rpc_config_mut(&mut self) -> &mut RpcConfig {
        self.rpc_config.get_or_insert_with(RpcConfig::default)
    }

    /// Set the active profile.
    pub fn set_active_profile(&mut self, name: Option<String>) {
        self.rpc_config_mut().active_profile = name;
    }

    /// Add or update an endpoint in a profile.
    pub fn upsert_profile_endpoint(&mut self, profile_name: &str, chain: &str, url: String) {
        let config = self.rpc_config_mut();
        let profile = config.profiles.entry(profile_name.to_string()).or_default();
        profile
            .chains
            .insert(chain.to_string(), ChainEndpoint { url });
    }

    /// Remove a chain endpoint from a profile. Deletes profile if empty.
    /// Clears active_profile if the deleted profile was the active one.
    pub fn remove_profile_endpoint(&mut self, profile_name: &str, chain: &str) -> bool {
        let config = match self.rpc_config.as_mut() {
            Some(c) => c,
            None => return false,
        };
        let profile = match config.profiles.get_mut(profile_name) {
            Some(p) => p,
            None => return false,
        };
        let removed = profile.chains.remove(chain).is_some();
        if removed && profile.chains.is_empty() {
            config.profiles.remove(profile_name);
            if config.active_profile.as_deref() == Some(profile_name) {
                config.active_profile = None;
            }
        }
        removed
    }

    /// Delete a profile entirely.
    pub fn delete_profile(&mut self, name: &str) -> bool {
        let config = match self.rpc_config.as_mut() {
            Some(c) => c,
            None => return false,
        };
        if config.profiles.remove(name).is_some() {
            if config.active_profile.as_deref() == Some(name) {
                config.active_profile = None;
            }
            true
        } else {
            false
        }
    }

    /// Load config from a file path, or return defaults if file doesn't exist.
    pub fn load(path: &std::path::Path) -> Result<Self, crate::error::OwsError> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let contents =
            std::fs::read_to_string(path).map_err(|e| crate::error::OwsError::InvalidInput {
                message: format!("failed to read config: {}", e),
            })?;
        serde_json::from_str(&contents).map_err(|e| crate::error::OwsError::InvalidInput {
            message: format!("failed to parse config: {}", e),
        })
    }

    /// Load `~/.ows/config.json`, merging user overrides on top of defaults.
    /// If the file doesn't exist, returns the built-in defaults.
    pub fn load_or_default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let config_path = PathBuf::from(home).join(".ows/config.json");
        Self::load_or_default_from(&config_path)
    }

    /// Load config from a specific path, merging user overrides on top of defaults.
    pub fn load_or_default_from(path: &std::path::Path) -> Self {
        let mut config = Config {
            // Start with empty rpc — built-in defaults come from `default_rpc()` at
            // runtime; this avoids baking them into the saved config file.
            rpc: HashMap::new(),
            ..Config::default()
        };
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(user_config) = serde_json::from_str::<Config>(&contents) {
                    // User overrides take priority for legacy rpc
                    for (k, v) in user_config.rpc {
                        config.rpc.insert(k, v);
                    }
                    config.plugins = user_config.plugins;
                    config.backup = user_config.backup;
                    if user_config.vault_path.as_path() != std::path::Path::new("/tmp/.ows")
                        && user_config.vault_path.to_string_lossy() != ""
                    {
                        config.vault_path = user_config.vault_path;
                    }
                    // New rpc_config takes precedence if present
                    if user_config.rpc_config.is_some() {
                        config.rpc_config = user_config.rpc_config;
                    }
                }
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_vault_path() {
        let config = Config::default();
        let path_str = config.vault_path.to_string_lossy();
        assert!(path_str.ends_with(".ows"));
    }

    #[test]
    fn test_serde_roundtrip_legacy_rpc() {
        let mut rpc = HashMap::new();
        rpc.insert(
            "eip155:1".to_string(),
            "https://eth.rpc.example".to_string(),
        );

        let config = Config {
            vault_path: PathBuf::from("/home/test/.ows"),
            rpc,
            rpc_config: None,
            plugins: HashMap::new(),
            backup: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let config2: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.vault_path, config2.vault_path);
        assert_eq!(config.rpc, config2.rpc);
    }

    #[test]
    fn test_rpc_lookup_hit() {
        let config = Config::default();
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://eth.llamarpc.com".to_string())
        );
    }

    #[test]
    fn test_default_rpc_endpoints() {
        let config = Config::default();
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://eth.llamarpc.com".to_string())
        );
        assert_eq!(
            config.rpc_url("eip155:137"),
            Some("https://polygon-rpc.com".to_string())
        );
        assert_eq!(
            config.rpc_url("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            Some("https://api.mainnet-beta.solana.com".to_string())
        );
    }

    #[test]
    fn test_rpc_lookup_miss() {
        let config = Config::default();
        assert_eq!(config.rpc_url("eip155:999"), None);
    }

    #[test]
    fn test_optional_backup() {
        let config = Config::default();
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_none());
    }

    #[test]
    fn test_backup_config_serde() {
        let config = Config {
            vault_path: PathBuf::from("/tmp/.ows"),
            rpc: HashMap::new(),
            rpc_config: None,
            plugins: HashMap::new(),
            backup: Some(BackupConfig {
                path: PathBuf::from("/tmp/backup"),
                auto_backup: Some(true),
                max_backups: Some(5),
            }),
        };
        let json = serde_json::to_value(&config).unwrap();
        assert!(json.get("backup").is_some());
        assert_eq!(json["backup"]["auto_backup"], true);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = Config::load(std::path::Path::new("/nonexistent/path/config.json")).unwrap();
        assert!(config.vault_path.to_string_lossy().ends_with(".ows"));
    }

    #[test]
    fn test_load_or_default_nonexistent() {
        let config = Config::load_or_default_from(std::path::Path::new("/nonexistent/config.json"));
        // rpc is empty (built-in defaults come from default_rpc() at runtime)
        assert!(config.rpc.is_empty());
        // rpc_url still resolves defaults via fallback
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://eth.llamarpc.com".to_string())
        );
    }

    #[test]
    fn test_load_or_default_merges_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "vault_path": "/tmp/custom-vault",
            "rpc": {
                "eip155:1": "https://custom-eth.rpc"
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://custom-eth.rpc".to_string())
        );
        assert_eq!(
            config.rpc_url("eip155:137"),
            Some("https://polygon-rpc.com".to_string())
        );
        assert_eq!(config.vault_path, PathBuf::from("/tmp/custom-vault"));
    }

    #[test]
    fn test_rpc_profile_serde() {
        let config = Config {
            vault_path: PathBuf::from("/tmp/.ows"),
            rpc: HashMap::new(),
            rpc_config: Some(RpcConfig {
                active_profile: Some("mainnet".into()),
                profiles: HashMap::from([(
                    "mainnet".into(),
                    RpcProfile {
                        chains: HashMap::from([(
                            "eip155:1".into(),
                            ChainEndpoint {
                                url: "https://profile-eth.example.com".into(),
                            },
                        )]),
                    },
                )]),
            }),
            plugins: HashMap::new(),
            backup: None,
        };
        let json = serde_json::to_string_pretty(&config).unwrap();
        let config2: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config2.rpc_config.as_ref().unwrap().active_profile,
            Some("mainnet".into())
        );
        assert_eq!(
            config2.profile_rpc_url("eip155:1"),
            Some("https://profile-eth.example.com")
        );
    }

    #[test]
    fn test_profile_rpc_url() {
        let mut config = Config::default();
        config.rpc_config = Some(RpcConfig {
            active_profile: Some("mainnet".into()),
            profiles: HashMap::from([(
                "mainnet".into(),
                RpcProfile {
                    chains: HashMap::from([(
                        "eip155:1".into(),
                        ChainEndpoint {
                            url: "https://profile-eth.example.com".into(),
                        },
                    )]),
                },
            )]),
        });

        assert_eq!(
            config.profile_rpc_url("eip155:1"),
            Some("https://profile-eth.example.com")
        );
        assert_eq!(config.profile_rpc_url("eip155:137"), None);
    }

    #[test]
    fn test_resolve_rpc_url_precedence() {
        let mut config = Config::default();
        config
            .rpc
            .insert("eip155:1".into(), "https://global-eth.example.com".into());
        config.rpc_config = Some(RpcConfig {
            active_profile: Some("mainnet".into()),
            profiles: HashMap::from([(
                "mainnet".into(),
                RpcProfile {
                    chains: HashMap::from([(
                        "eip155:1".into(),
                        ChainEndpoint {
                            url: "https://profile-eth.example.com".into(),
                        },
                    )]),
                },
            )]),
        });

        // Explicit override takes precedence
        assert_eq!(
            config.resolve_rpc_url("eip155:1", Some("https://explicit.example.com")),
            Some("https://explicit.example.com".to_string())
        );
        // Active profile takes precedence over global
        assert_eq!(
            config.resolve_rpc_url("eip155:1", None),
            Some("https://profile-eth.example.com".to_string())
        );
        // Fallback to global
        assert_eq!(
            config.resolve_rpc_url("eip155:137", None),
            Some("https://polygon-rpc.com".to_string())
        );
        // Unknown chain, no default
        assert_eq!(config.resolve_rpc_url("eip155:999", None), None);
    }

    #[test]
    fn test_load_or_default_merges_rpc_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "vault_path": "/tmp/.ows",
            "rpc_config": {
                "activeProfile": "mainnet",
                "profiles": {
                    "mainnet": {
                        "chains": {
                            "eip155:1": { "url": "https://custom-profile.eth" }
                        }
                    }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        assert_eq!(config.active_profile(), Some("mainnet"));
        assert_eq!(
            config.profile_rpc_url("eip155:1"),
            Some("https://custom-profile.eth")
        );
        // Defaults still present via legacy rpc
        assert_eq!(
            config.rpc_url("eip155:137"),
            Some("https://polygon-rpc.com".to_string())
        );
    }

    #[test]
    fn test_backward_compat_old_config_loads() {
        // Simulates an old config file with flat rpc hashmap
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let old_config = serde_json::json!({
            "vault_path": "/tmp/.ows",
            "rpc": {
                "eip155:1": "https://old-custom.eth"
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&old_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        // Old flat rpc is preserved
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://old-custom.eth".to_string())
        );
        // rpc_config is None since old format doesn't have it
        assert!(config.rpc_config.is_none());
    }

    #[test]
    fn test_new_config_takes_precedence_over_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let user_config = serde_json::json!({
            "vault_path": "/tmp/.ows",
            "rpc": {
                "eip155:1": "https://legacy.eth"
            },
            "rpc_config": {
                "activeProfile": "new",
                "profiles": {
                    "new": {
                        "chains": {
                            "eip155:1": { "url": "https://new-profile.eth" }
                        }
                    }
                }
            }
        });
        std::fs::write(&config_path, serde_json::to_string(&user_config).unwrap()).unwrap();

        let config = Config::load_or_default_from(&config_path);
        // New config takes precedence for profile lookups
        assert_eq!(
            config.resolve_rpc_url("eip155:1", None),
            Some("https://new-profile.eth".to_string())
        );
        // But legacy rpc is still accessible directly
        assert_eq!(
            config.rpc_url("eip155:1"),
            Some("https://legacy.eth".to_string())
        );
    }

    #[test]
    fn test_profile_helpers() {
        let mut config = Config::default();

        // upsert_profile_endpoint
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.upsert_profile_endpoint("dev", "solana", "https://dev-sol.example.com".into());
        assert_eq!(
            config.profile("dev").unwrap().endpoint("eip155:1"),
            Some("https://dev-eth.example.com")
        );

        // set_active_profile
        config.set_active_profile(Some("dev".into()));
        assert_eq!(config.active_profile(), Some("dev"));

        // remove_profile_endpoint
        assert!(config.remove_profile_endpoint("dev", "eip155:1"));
        assert_eq!(config.profile("dev").unwrap().endpoint("eip155:1"), None);
        assert_eq!(
            config.profile("dev").unwrap().endpoint("solana"),
            Some("https://dev-sol.example.com")
        );

        // Deleting last chain removes profile
        assert!(config.remove_profile_endpoint("dev", "solana"));
        assert!(config.profile("dev").is_none());
    }

    #[test]
    fn test_delete_profile_clears_active() {
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.set_active_profile(Some("dev".into()));

        assert!(config.delete_profile("dev"));
        assert!(config.profile("dev").is_none());
        assert_eq!(config.active_profile(), None);
    }

    #[test]
    fn test_remove_last_chain_clears_active() {
        // Regression: removing the last chain from the active profile via
        // remove_profile_endpoint should clear active_profile.
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.set_active_profile(Some("dev".into()));

        assert_eq!(config.active_profile(), Some("dev"));
        assert!(config.remove_profile_endpoint("dev", "eip155:1"));
        assert!(config.profile("dev").is_none());
        assert_eq!(config.active_profile(), None);
    }

    #[test]
    fn test_delete_profile_nonexistent() {
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());

        // Deleting nonexistent profile returns false
        assert!(!config.delete_profile("nonexistent"));
        // Original profile still exists
        assert!(config.profile("dev").is_some());
    }

    #[test]
    fn test_delete_profile_inactive_does_not_clear_active() {
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.upsert_profile_endpoint("prod", "eip155:1", "https://prod-eth.example.com".into());
        config.set_active_profile(Some("prod".into()));

        // Deleting inactive profile doesn't affect active
        assert!(config.delete_profile("dev"));
        assert_eq!(config.active_profile(), Some("prod"));
    }

    #[test]
    fn test_remove_profile_endpoint_nonexistent_profile() {
        let mut config = Config::default();
        // Removing from nonexistent profile returns false
        assert!(!config.remove_profile_endpoint("nonexistent", "eip155:1"));
    }

    #[test]
    fn test_remove_profile_endpoint_nonexistent_chain() {
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());

        // Removing nonexistent chain returns false
        assert!(!config.remove_profile_endpoint("dev", "eip155:999"));
        // Original chain still exists
        assert_eq!(
            config.profile("dev").unwrap().endpoint("eip155:1"),
            Some("https://dev-eth.example.com")
        );
    }

    #[test]
    fn test_update_existing_chain_in_profile() {
        let mut config = Config::default();
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth-v2.example.com".into());

        // Should have new URL
        assert_eq!(
            config.profile("dev").unwrap().endpoint("eip155:1"),
            Some("https://dev-eth-v2.example.com")
        );
    }

    #[test]
    fn test_active_profile_returns_none_when_not_set() {
        let config = Config::default();
        assert_eq!(config.active_profile(), None);
    }

    #[test]
    fn test_profile_names_empty_when_no_profiles() {
        let config = Config::default();
        assert!(config.profile_names().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn test_save_config_does_not_bake_in_defaults() {
        // Regression: saving a config with only profile-based RPC should NOT
        // write the built-in defaults into the rpc field.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");

        // Build a config that only has a profile (no global rpc overrides)
        let mut config = Config::load_or_default_from(&config_path);
        config.upsert_profile_endpoint("dev", "eip155:1", "https://dev-eth.example.com".into());
        config.set_active_profile(Some("dev".into()));

        // Serialize and write to disk (as CLI save does)
        let json = serde_json::to_string(&config).unwrap();
        std::fs::write(&config_path, &json).unwrap();

        // Read back as Value and verify rpc field is absent/empty
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // rpc field must be absent or empty — no baked-in defaults
        let rpc = parsed.get("rpc");
        assert!(
            rpc.is_none() || rpc == Some(&serde_json::Value::Object(Default::default())),
            "rpc field should be absent or empty, got: {:?}",
            rpc
        );

        // profiles should be present
        assert!(
            parsed
                .get("rpc_config")
                .and_then(|c| c.get("profiles"))
                .is_some(),
            "profiles should be saved"
        );

        // Reload from disk and verify profile still works
        let reloaded = Config::load_or_default_from(&config_path);
        assert_eq!(
            reloaded.profile_rpc_url("eip155:1"),
            Some("https://dev-eth.example.com")
        );
    }
}
