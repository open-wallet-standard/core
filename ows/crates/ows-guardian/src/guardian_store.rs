use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GuardianError;
use crate::types::GuardianConfig;

#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    let _ = fs::set_permissions(path, perms);
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    let _ = fs::set_permissions(path, perms);
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

fn guardians_dir(vault_path: Option<&Path>) -> Result<PathBuf, GuardianError> {
    let base = match vault_path {
        Some(p) => p.to_path_buf(),
        None => ows_core::Config::default().vault_path,
    };
    let dir = base.join("guardians");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&base);
    set_dir_permissions(&dir);
    Ok(dir)
}

pub fn save_guardian_config(
    config: &GuardianConfig,
    vault_path: Option<&Path>,
) -> Result<(), GuardianError> {
    let dir = guardians_dir(vault_path)?;
    let path = dir.join(format!("{}.json", config.wallet_id));
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

pub fn load_guardian_config(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<GuardianConfig, GuardianError> {
    let dir = guardians_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet_id));
    if !path.exists() {
        return Err(GuardianError::ConfigNotFound(wallet_id.to_string()));
    }
    let contents = fs::read_to_string(&path)?;
    let config: GuardianConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

pub fn delete_guardian_config(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<(), GuardianError> {
    let dir = guardians_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet_id));
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

pub fn list_guardian_configs(
    vault_path: Option<&Path>,
) -> Result<Vec<GuardianConfig>, GuardianError> {
    let dir = guardians_dir(vault_path)?;
    let mut configs = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(configs),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<GuardianConfig>(&contents) {
                Ok(c) => configs.push(c),
                Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
            },
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }

    Ok(configs)
}
