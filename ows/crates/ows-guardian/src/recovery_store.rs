use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GuardianError;
use crate::types::RecoveryRequest;

#[cfg(unix)]
fn set_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) {}

#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) {}

fn recovery_dir(vault_path: Option<&Path>) -> Result<PathBuf, GuardianError> {
    let base = match vault_path {
        Some(p) => p.to_path_buf(),
        None => ows_core::Config::default().vault_path,
    };
    let dir = base.join("recovery");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(&base);
    set_dir_permissions(&dir);
    Ok(dir)
}

pub fn save_recovery(
    request: &RecoveryRequest,
    vault_path: Option<&Path>,
) -> Result<(), GuardianError> {
    let dir = recovery_dir(vault_path)?;
    let path = dir.join(format!("{}.json", request.wallet_id));
    let json = serde_json::to_string_pretty(request)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

pub fn load_recovery(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<RecoveryRequest, GuardianError> {
    let dir = recovery_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet_id));
    if !path.exists() {
        return Err(GuardianError::RecoveryNotFound(wallet_id.to_string()));
    }
    let contents = fs::read_to_string(&path)?;
    let request: RecoveryRequest = serde_json::from_str(&contents)?;
    Ok(request)
}

pub fn delete_recovery(wallet_id: &str, vault_path: Option<&Path>) -> Result<(), GuardianError> {
    let dir = recovery_dir(vault_path)?;
    let path = dir.join(format!("{}.json", wallet_id));
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}
