use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

pub fn run(purge: bool) -> Result<(), crate::CliError> {
    let install_dir = install_dir();
    let binary = install_dir.join("ows");
    let vault_path = vault_path();

    if !binary.exists() && !purge {
        println!(
            "ows binary not found at {} — already uninstalled?",
            binary.display()
        );
        return Ok(());
    }

    // Show what will be removed
    println!("This will remove:");
    if binary.exists() {
        println!("  - {}", binary.display());
    }
    if install_dir.exists() {
        println!("  - {} (install directory)", install_dir.display());
    }
    if purge {
        println!("  - {} (all wallet data and config)", vault_path.display());
    }
    println!("  - PATH entries from shell config files");
    println!();

    // Confirm
    print!("Continue? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !answer.trim().eq_ignore_ascii_case("y") {
        println!("Aborted.");
        return Ok(());
    }

    // Remove binary and install dir
    if binary.exists() {
        std::fs::remove_file(&binary)
            .map_err(|e| crate::CliError::InvalidArgs(format!("failed to remove binary: {e}")))?;
        println!("Removed {}", binary.display());
    }

    // Remove install dir if empty
    if install_dir.exists()
        && std::fs::read_dir(&install_dir)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false)
    {
        std::fs::remove_dir(&install_dir).ok();
    }

    // Purge vault data
    if purge && vault_path.exists() {
        std::fs::remove_dir_all(&vault_path).map_err(|e| {
            crate::CliError::InvalidArgs(format!("failed to remove vault data: {e}"))
        })?;
        println!("Removed {}", vault_path.display());
    }

    // Uninstall language bindings
    uninstall_node_bindings();
    uninstall_python_bindings();

    // Clean PATH from shell configs
    remove_path_entries(&install_dir);

    println!();
    println!("ows has been uninstalled.");
    if !purge {
        println!(
            "Wallet data remains at {}. Use --purge to remove it.",
            vault_path.display()
        );
    }

    Ok(())
}

fn install_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else if let Ok(dir) = std::env::var("LWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else {
        home_dir().join(".ows/bin")
    }
}

fn vault_path() -> PathBuf {
    home_dir().join(".ows")
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn uninstall_node_bindings() {
    if Command::new("npm").arg("--version").output().is_err() {
        return;
    }
    let check = Command::new("npm")
        .args(["list", "-g", "@open-wallet-standard/node"])
        .output();
    if let Ok(output) = check {
        if output.status.success() {
            println!("Removing Node bindings...");
            let _ = Command::new("npm")
                .args(["uninstall", "-g", "@open-wallet-standard/node"])
                .status();
        }
    }
}

fn uninstall_python_bindings() {
    // Try pip3 first, then python3 -m pip
    let result = Command::new("pip3")
        .args(["show", "open-wallet-standard"])
        .output();
    let installed = matches!(result, Ok(ref o) if o.status.success());

    if installed {
        println!("Removing Python bindings...");
        let _ = Command::new("pip3")
            .args(["uninstall", "-y", "open-wallet-standard"])
            .status();
        return;
    }

    let result = Command::new("python3")
        .args(["-m", "pip", "show", "open-wallet-standard"])
        .output();
    if let Ok(output) = result {
        if output.status.success() {
            println!("Removing Python bindings...");
            let _ = Command::new("python3")
                .args(["-m", "pip", "uninstall", "-y", "open-wallet-standard"])
                .status();
        }
    }
}

fn remove_path_entries(install_dir: &std::path::Path) {
    let dir_str = install_dir.to_string_lossy();

    let rc_files = [
        home_dir().join(".zshrc"),
        home_dir().join(".bashrc"),
        home_dir().join(".bash_profile"),
        home_dir().join(".config/fish/config.fish"),
    ];

    for rc in &rc_files {
        if !rc.exists() {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(rc) else {
            continue;
        };
        if !contents.contains(dir_str.as_ref()) {
            continue;
        }
        let filtered: Vec<&str> = contents
            .lines()
            .filter(|line| !line.contains(dir_str.as_ref()))
            .collect();
        let new_contents = filtered.join("\n");
        // Preserve trailing newline if original had one
        let new_contents = if contents.ends_with('\n') {
            format!("{new_contents}\n")
        } else {
            new_contents
        };
        if std::fs::write(rc, &new_contents).is_ok() {
            println!("Cleaned PATH from {}", rc.display());
        }
    }
}
