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

    println!();
    println!("RPC endpoints:");

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
