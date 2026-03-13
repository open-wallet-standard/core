use std::path::PathBuf;

/// Migrate the vault directory from `~/.lws` to `~/.ows` if needed.
///
/// This is a one-time upgrade path for users who installed `lws` before the
/// rename to `ows`. It also updates shell RC files to point PATH at `.ows/bin`.
pub fn migrate_vault_if_needed() {
    let Some(home) = std::env::var("HOME").ok() else {
        return;
    };

    let old_dir = PathBuf::from(&home).join(".lws");
    let new_dir = PathBuf::from(&home).join(".ows");

    if old_dir.exists() && !new_dir.exists() {
        // Attempt atomic rename (same filesystem)
        if let Err(e) = std::fs::rename(&old_dir, &new_dir) {
            eprintln!(
                "warning: failed to migrate {} to {}: {e}",
                old_dir.display(),
                new_dir.display()
            );
            return;
        }

        // Update vault_path in config.json if present
        let config_path = new_dir.join("config.json");
        if config_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&config_path) {
                let updated = contents.replace(".lws", ".ows");
                let _ = std::fs::write(&config_path, updated);
            }
        }

        // Update PATH in shell rc files
        let rc_files = [
            PathBuf::from(&home).join(".zshrc"),
            PathBuf::from(&home).join(".bashrc"),
            PathBuf::from(&home).join(".bash_profile"),
            PathBuf::from(&home).join(".config/fish/config.fish"),
        ];

        for rc in &rc_files {
            if rc.exists() {
                if let Ok(contents) = std::fs::read_to_string(rc) {
                    if contents.contains(".lws/bin") {
                        let updated = contents.replace(".lws/bin", ".ows/bin");
                        let _ = std::fs::write(rc, updated);
                    }
                }
            }
        }

        eprintln!("Migrated wallet vault from ~/.lws to ~/.ows");
    } else if old_dir.exists() && new_dir.exists() {
        eprintln!(
            "warning: Both ~/.lws and ~/.ows exist. Using ~/.ows. Remove ~/.lws manually if no longer needed."
        );
    }
}
