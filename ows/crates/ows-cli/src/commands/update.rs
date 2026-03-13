use std::path::PathBuf;
use std::process::Command;

const REPO: &str = "open-wallet-standard/core";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run(force: bool) -> Result<(), crate::CliError> {
    let install_dir = install_dir();

    let tag = get_latest_tag()?;
    let latest_version = tag.strip_prefix('v').unwrap_or(&tag);

    println!("installed: v{CURRENT_VERSION}");
    println!("   latest: {tag}");

    if !force && latest_version == CURRENT_VERSION {
        println!("Already up to date.");
        return Ok(());
    }

    if force {
        println!("Forcing update...");
    } else {
        println!("Downloading update...");
    }

    let platform = detect_platform()?;
    let binary_url = format!("https://github.com/{REPO}/releases/download/{tag}/ows-{platform}");

    let tmp = tempfile::NamedTempFile::new()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create temp file: {e}")))?;
    let tmp_path = tmp.path().to_path_buf();

    // Download the binary
    download_binary(&binary_url, &tmp_path)?;

    // Install it
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to create install dir: {e}")))?;

    let dest = install_dir.join("ows");
    std::fs::copy(&tmp_path, &dest)
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to copy binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| crate::CliError::InvalidArgs(format!("failed to set permissions: {e}")))?;
    }

    println!("Updated ows to {tag}");

    // Trigger vault migration in case the user is upgrading from lws
    ows_lib::migrate::migrate_vault_if_needed();

    // Update language bindings
    update_node_bindings();
    update_python_bindings();

    Ok(())
}

/// Update Node.js bindings if npm is available.
fn update_node_bindings() {
    if Command::new("npm").arg("--version").output().is_err() {
        return;
    }

    // Check if already installed
    let check = Command::new("npm")
        .args(["list", "-g", "@open-wallet-standard/node"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            println!("Updating Node bindings...");
            let status = Command::new("npm")
                .args(["install", "-g", "@open-wallet-standard/node@latest"])
                .status();
            match status {
                Ok(s) if s.success() => println!("Node bindings updated."),
                _ => eprintln!("warn: failed to update Node bindings"),
            }
        }
        _ => {} // not installed, skip
    }
}

/// Update Python bindings if pip is available.
fn update_python_bindings() {
    // Try pip3 first, then python3 -m pip
    let pip_cmd = if Command::new("pip3").arg("--version").output().is_ok() {
        Some(("pip3", vec![]))
    } else if Command::new("python3")
        .args(["-m", "pip", "--version"])
        .output()
        .is_ok()
    {
        Some(("python3", vec!["-m", "pip"]))
    } else {
        None
    };

    let Some((cmd, prefix)) = pip_cmd else {
        return;
    };

    // Check if already installed
    let mut check = Command::new(cmd);
    for arg in &prefix {
        check.arg(arg);
    }
    check.args(["show", "open-wallet-standard"]);

    match check.output() {
        Ok(output) if output.status.success() => {
            println!("Updating Python bindings...");
            let mut upgrade = Command::new(cmd);
            for arg in &prefix {
                upgrade.arg(arg);
            }
            upgrade.args(["install", "--upgrade", "open-wallet-standard"]);
            match upgrade.status() {
                Ok(s) if s.success() => println!("Python bindings updated."),
                _ => eprintln!("warn: failed to update Python bindings"),
            }
        }
        _ => {} // not installed, skip
    }
}

/// Fetch the latest release tag from GitHub API using curl.
fn get_latest_tag() -> Result<String, crate::CliError> {
    let api_url = format!("https://api.github.com/repos/{REPO}/releases/latest");

    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-H",
            "Accept: application/vnd.github+json",
            &api_url,
        ])
        .output()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        return Err(crate::CliError::InvalidArgs(
            "failed to fetch latest release — check your network connection".to_string(),
        ));
    }

    let body = String::from_utf8_lossy(&output.stdout);

    extract_json_string(&body, "tag_name").ok_or_else(|| {
        crate::CliError::InvalidArgs(
            "no releases found — push a version tag (e.g. v0.2.0) to create one".to_string(),
        )
    })
}

/// Download a binary from a URL using curl.
fn download_binary(url: &str, dest: &std::path::Path) -> Result<(), crate::CliError> {
    let dest_str = dest.to_str().unwrap_or("download");

    let status = Command::new("curl")
        .args(["-fsSL", "-o", dest_str, url])
        .status()
        .map_err(|e| crate::CliError::InvalidArgs(format!("failed to run curl: {e}")))?;

    if !status.success() {
        return Err(crate::CliError::InvalidArgs(format!(
            "failed to download binary from {url} — no prebuilt binary for your platform?"
        )));
    }

    Ok(())
}

/// Detect the current platform in the same format as release assets.
fn detect_platform() -> Result<String, crate::CliError> {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        return Err(crate::CliError::InvalidArgs(
            "unsupported OS for prebuilt binaries".to_string(),
        ));
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return Err(crate::CliError::InvalidArgs(
            "unsupported architecture for prebuilt binaries".to_string(),
        ));
    };

    Ok(format!("{os}-{arch}"))
}

/// Minimal JSON string extractor (avoids serde dependency for this one command).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    // skip `: "`  or `:"`
    let rest = rest
        .trim_start()
        .strip_prefix(':')?
        .trim_start()
        .strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn install_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else if let Ok(dir) = std::env::var("LWS_INSTALL_DIR") {
        PathBuf::from(dir)
    } else {
        dirs_or_home().join(".ows/bin")
    }
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}
