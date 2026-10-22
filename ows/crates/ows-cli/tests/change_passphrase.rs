use std::fs;
use std::process::{Command, Output, Stdio};

fn command(home: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ows"));
    command
        .env("HOME", home)
        .env_remove("OWS_PASSPHRASE")
        .env_remove("LWS_PASSPHRASE")
        .env_remove("OWS_NEW_PASSPHRASE")
        .stdin(Stdio::null())
        .arg("wallet")
        .arg("change-passphrase");
    command
}

fn assert_no_passwords(output: &Output) {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("old-test-password"));
    assert!(!text.contains("new-test-password"));
}

#[test]
fn cli_changes_password_without_printing_secrets_or_creating_backups() {
    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join(".ows");
    let wallet = ows_lib::create_wallet(
        "cli-wallet",
        Some(12),
        Some("old-test-password"),
        Some(&vault),
    )
    .unwrap();
    let output = command(directory.path())
        .args(["--wallet", &wallet.id])
        .env("OWS_PASSPHRASE", "old-test-password")
        .env("OWS_NEW_PASSPHRASE", "new-test-password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_passwords(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Existing API keys remain valid"));
    assert!(ows_lib::export_wallet(&wallet.id, Some("old-test-password"), Some(&vault)).is_err());
    assert!(ows_lib::export_wallet(&wallet.id, Some("new-test-password"), Some(&vault)).is_ok());
    let audit = fs::read_to_string(vault.join("logs/audit.jsonl")).unwrap();
    assert!(audit.contains("change_wallet_passphrase"));
    assert!(!audit.contains("old-test-password") && !audit.contains("new-test-password"));
}

#[test]
fn cli_requires_explicit_credentials_and_preserves_wallet_on_errors() {
    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join(".ows");
    let wallet = ows_lib::create_wallet(
        "cli-wallet",
        Some(12),
        Some("old-test-password"),
        Some(&vault),
    )
    .unwrap();
    let path = vault.join("wallets").join(format!("{}.json", wallet.id));
    let original = fs::read(&path).unwrap();
    for (old, new) in [
        (None, Some("new-test-password")),
        (Some("old-test-password"), None),
        (Some("wrong"), Some("new-test-password")),
        (Some("old-test-password"), Some("")),
    ] {
        let mut command = command(directory.path());
        command.args(["--wallet", "cli-wallet"]);
        if let Some(old) = old {
            command.env("OWS_PASSPHRASE", old);
        }
        if let Some(new) = new {
            command.env("OWS_NEW_PASSPHRASE", new);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert_no_passwords(&output);
        assert_eq!(fs::read(&path).unwrap(), original);
    }
    // No flags that could put passwords in process listings are accepted.
    let output = command(directory.path())
        .args([
            "--wallet",
            "cli-wallet",
            "--new-passphrase",
            "new-test-password",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn cli_can_protect_a_wallet_with_an_initially_empty_password() {
    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join(".ows");
    let wallet = ows_lib::create_wallet("empty-wallet", Some(12), None, Some(&vault)).unwrap();
    let output = command(directory.path())
        .args(["--wallet", "empty-wallet"])
        .env("OWS_PASSPHRASE", "")
        .env("OWS_NEW_PASSPHRASE", "new-test-password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_passwords(&output);
    assert!(ows_lib::export_wallet(&wallet.id, Some("new-test-password"), Some(&vault)).is_ok());
}

#[test]
fn cli_respects_password_environment_precedence_and_legacy_fallback() {
    for (password, ows, legacy, success) in [
        ("old", None, Some("old"), true),
        ("old", Some("old"), Some("wrong"), true),
        ("old", Some("wrong"), Some("old"), false),
        ("old", Some(""), Some("old"), false),
        ("", Some(""), Some("wrong"), true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let vault = directory.path().join(".ows");
        let wallet =
            ows_lib::create_wallet("cli-wallet", Some(12), Some(password), Some(&vault)).unwrap();
        let path = vault.join("wallets").join(format!("{}.json", wallet.id));
        let original = fs::read(&path).unwrap();
        let new_password = "  café 🔒 密码  ";
        let mut command = command(directory.path());
        command
            .args(["--wallet", "cli-wallet"])
            .env("OWS_NEW_PASSPHRASE", new_password);
        if let Some(value) = ows {
            command.env("OWS_PASSPHRASE", value);
        }
        if let Some(value) = legacy {
            command.env("LWS_PASSPHRASE", value);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.success(), success);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(new_password));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(new_password));
        if success {
            assert!(ows_lib::export_wallet(&wallet.id, Some(new_password), Some(&vault)).is_ok());
        } else {
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}
