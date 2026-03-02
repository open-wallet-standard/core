use lws_core::{Config, WalletDescriptor};
use std::fs;
use std::path::PathBuf;

use crate::CliError;

/// Set directory permissions to 0o700 (owner-only).
#[cfg(unix)]
fn set_dir_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o700);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!("warning: failed to set permissions on {}: {e}", path.display());
    }
}

/// Set file permissions to 0o600 (owner read/write only).
#[cfg(unix)]
fn set_file_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = fs::Permissions::from_mode(0o600);
    if let Err(e) = fs::set_permissions(path, perms) {
        eprintln!("warning: failed to set permissions on {}: {e}", path.display());
    }
}

/// Warn if a directory has permissions more open than 0o700.
#[cfg(unix)]
pub fn check_vault_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            eprintln!(
                "warning: {} has permissions {:04o}, expected 0700",
                path.display(),
                mode
            );
        }
    }
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &std::path::Path) {}

#[cfg(not(unix))]
fn set_file_permissions(_path: &std::path::Path) {}

#[cfg(not(unix))]
pub fn check_vault_permissions(_path: &std::path::Path) {}

/// Returns the wallets directory, creating it if necessary.
pub fn wallets_dir() -> Result<PathBuf, CliError> {
    let config = Config::default();
    let lws_dir = &config.vault_path;
    let dir = lws_dir.join("wallets");
    fs::create_dir_all(&dir)?;
    set_dir_permissions(lws_dir);
    set_dir_permissions(&dir);
    Ok(dir)
}

/// Save a wallet descriptor as pretty JSON.
pub fn save_wallet(wallet: &WalletDescriptor) -> Result<(), CliError> {
    let dir = wallets_dir()?;
    let path = dir.join(format!("{}.json", wallet.id));
    let json = serde_json::to_string_pretty(wallet)?;
    fs::write(&path, json)?;
    set_file_permissions(&path);
    Ok(())
}

/// Load all wallet descriptors from the wallets directory.
/// Skips malformed files with a warning to stderr.
/// Returns wallets sorted by created_at descending (newest first).
pub fn list_wallets() -> Result<Vec<WalletDescriptor>, CliError> {
    let dir = wallets_dir()?;
    check_vault_permissions(&dir);

    let mut wallets = Vec::new();

    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(wallets),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<WalletDescriptor>(&contents) {
                Ok(w) => wallets.push(w),
                Err(e) => {
                    eprintln!("warning: skipping {}: {e}", path.display());
                }
            },
            Err(e) => {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }

    wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(wallets)
}
