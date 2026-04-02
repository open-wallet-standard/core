use ows_core::Config;
use std::path::PathBuf;

use crate::CliError;

pub fn show() -> Result<(), CliError> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let config_path = PathBuf::from(&home).join(".ows/config.json");
    let config_exists = config_path.exists();

    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    println!("Vault:  {}", config.vault_path.display());
    if config_exists {
        println!("Config: {}", config_path.display());
    } else {
        println!(
            "Config: {} (not found — using defaults)",
            config_path.display()
        );
    }

    // Show active profile
    println!();
    println!(
        "Active profile: {}",
        config.active_profile().unwrap_or("(none)")
    );

    // Show active profile endpoints if one is set
    if let Some(profile_name) = config.active_profile() {
        if let Some(profile) = config.profile(profile_name) {
            println!("Profile endpoints ({}):", profile_name);
            for (chain, url) in profile.endpoints() {
                println!("  {:<40} {}", chain, url);
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

    // Show available profiles
    let profile_count = config.profile_names().count();
    if profile_count > 0 {
        println!();
        println!("Available profiles ({}):", profile_count);
        for name in config.profile_names() {
            let marker = if config.active_profile() == Some(name) {
                " (active)"
            } else {
                ""
            };
            if let Some(profile) = config.profile(name) {
                println!("  {}{} ({} chains)", name, marker, profile.chains.len());
            }
        }
    }

    Ok(())
}
