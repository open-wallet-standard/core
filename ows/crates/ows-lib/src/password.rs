use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use ows_core::EncryptedWallet;
use ows_signer::{crypto::reencrypt_with_passphrase, CryptoEnvelope};

use crate::{ops::wallet_to_info, vault, OwsLibError, WalletInfo};

/// Re-encrypt one existing wallet with a new, nonempty owner passphrase.
///
/// The old passphrase is required (use `""` for an initially empty passphrase).
/// The secret stays in zeroizing memory; wallet identity, accounts, metadata and
/// unknown wallet-level JSON fields are preserved. Fresh salt and IV are generated using the
/// existing scrypt/AES-GCM format. API keys and their policies are unchanged.
/// This does not rotate signing keys or invalidate old backups/API tokens.
///
/// Password changes on the same file are serialized with a nonblocking OS lock.
/// Other wallet writers must be stopped: they do not participate in this lock.
/// A changed snapshot is rejected before atomic replacement, but this is not a
/// general transaction protocol for concurrent rename/delete/import operations.
/// Pre-commit errors leave the original file intact. The replacement file is
/// synced before rename; power-loss durability of the directory entry is subject
/// to the filesystem. No plaintext backup is written.
pub fn change_wallet_passphrase(
    name_or_id: &str,
    old_passphrase: &str,
    new_passphrase: &str,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, OwsLibError> {
    if new_passphrase.is_empty() || new_passphrase.starts_with("ows_key_") {
        return Err(OwsLibError::InvalidInput(
            "new passphrase must be nonempty and must not use the API-token prefix".into(),
        ));
    }
    let (path, expected_id) = find_wallet(name_or_id, vault_path)?;
    for directory in [
        vault::resolve_vault_path(vault_path),
        path.parent().unwrap().to_path_buf(),
    ] {
        if fs::metadata(directory)?.permissions().readonly() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "wallet directory is read-only",
            )
            .into());
        }
    }
    // Keep this file on disk: unlinking a lock file can let concurrent callers
    // lock different inodes. The OS releases the lock on close/process exit.
    let _lock = lock_wallet(&path)?;
    let original = fs::read(&path)?;
    let mut document: serde_json::Value = serde_json::from_slice(&original)?;
    let wallet: EncryptedWallet = serde_json::from_value(document.clone())?;
    if wallet.id != expected_id || (wallet.id != name_or_id && wallet.name != name_or_id) {
        return Err(OwsLibError::InvalidInput(
            "wallet changed; retry the operation".into(),
        ));
    }
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    if envelope.kdf != "scrypt" {
        return Err(OwsLibError::InvalidInput(
            "password changes require a passphrase-encrypted wallet".into(),
        ));
    }
    let replacement = reencrypt_with_passphrase(&envelope, old_passphrase, new_passphrase)?;
    document["crypto"] = serde_json::to_value(replacement)?;
    replace_wallet_file(&path, &original, &document)?;
    Ok(wallet_to_info(&wallet))
}

// Resolve without wallets_dir(): this operation must not create a missing vault
// or relax an existing directory's permissions just to read a wallet.
fn find_wallet(query: &str, vault_path: Option<&Path>) -> Result<(PathBuf, String), OwsLibError> {
    let directory = vault::resolve_vault_path(vault_path).join("wallets");
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OwsLibError::WalletNotFound(query.into()));
        }
        Err(e) => return Err(e.into()),
    };
    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() || entry.path().extension().is_none_or(|e| e != "json") {
            continue;
        }
        let contents = fs::read(entry.path())?;
        let Ok(wallet) = serde_json::from_slice::<EncryptedWallet>(&contents) else {
            continue;
        };
        if wallet.id == query {
            return Ok((entry.path(), wallet.id));
        }
        if wallet.name == query {
            matches.push((entry.path(), wallet.id));
        }
    }
    match matches.len() {
        0 => Err(OwsLibError::WalletNotFound(query.into())),
        1 => Ok(matches.remove(0)),
        count => Err(OwsLibError::AmbiguousWallet {
            name: query.into(),
            count,
        }),
    }
}

fn lock_wallet(path: &Path) -> Result<File, OwsLibError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock_path = path.with_extension("passphrase.lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if !metadata.is_file() {
            return Err(OwsLibError::InvalidInput(
                "wallet lock is not a regular file".into(),
            ));
        }
    }
    let file = options.open(lock_path)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(OwsLibError::InvalidInput(
            "another password change is in progress for this wallet".into(),
        )),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

fn replace_wallet_file(
    path: &Path,
    original: &[u8],
    document: &serde_json::Value,
) -> Result<(), OwsLibError> {
    if fs::symlink_metadata(path)?.file_type().is_symlink()
        || fs::metadata(path)?.permissions().readonly()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "wallet is read-only or a symbolic link",
        )
        .into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| OwsLibError::InvalidInput("wallet has no parent directory".into()))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".ows-passphrase-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut temporary, document)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    if fs::read(path)? != original {
        return Err(OwsLibError::InvalidInput(
            "wallet changed; retry the operation".into(),
        ));
    }
    temporary
        .persist(path)
        .map_err(|e| OwsLibError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{key_ops, key_store, ops, policy_store};
    use ows_core::{KeyType, Policy, PolicyAction, PolicyRule};
    use ows_signer::encrypt;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn fixture(vault: &Path, password: &str, key_type: KeyType) -> PathBuf {
        let secret = if key_type == KeyType::Mnemonic {
            MNEMONIC
        } else {
            r#"{"secp256k1":"0123456789abcdef","ed25519":"abcdef"}"#
        };
        let envelope = encrypt(secret.as_bytes(), password).unwrap();
        let wallet = EncryptedWallet::new(
            "wallet-id".into(),
            "fixture".into(),
            vec![],
            serde_json::to_value(envelope).unwrap(),
            key_type,
        );
        vault::save_encrypted_wallet(&wallet, Some(vault)).unwrap();
        vault.join("wallets/wallet-id.json")
    }

    #[test]
    fn changes_password_preserving_secret_identity_and_unknown_fields() {
        for key_type in [KeyType::Mnemonic, KeyType::PrivateKey] {
            let directory = tempfile::tempdir().unwrap();
            let path = fixture(directory.path(), "old", key_type);
            let mut before: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            before["metadata"] = serde_json::json!({"label":"preserve me"});
            before["future_extension"] = serde_json::json!({"version":3});
            fs::write(&path, serde_json::to_vec(&before).unwrap()).unwrap();
            let old_secret =
                ops::export_wallet("fixture", Some("old"), Some(directory.path())).unwrap();
            let info =
                change_wallet_passphrase("fixture", "old", "new", Some(directory.path())).unwrap();
            assert_eq!(info.id, "wallet-id");
            assert_eq!(
                ops::export_wallet("wallet-id", Some("new"), Some(directory.path())).unwrap(),
                old_secret
            );
            assert!(ops::export_wallet("fixture", Some("old"), Some(directory.path())).is_err());
            let mut after: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_ne!(
                before["crypto"]["kdfparams"]["salt"],
                after["crypto"]["kdfparams"]["salt"]
            );
            assert_ne!(
                before["crypto"]["cipherparams"]["iv"],
                after["crypto"]["cipherparams"]["iv"]
            );
            after["crypto"] = before["crypto"].clone();
            assert_eq!(after, before);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ows-passphrase-")));
        }
    }

    #[test]
    fn wrong_password_and_invalid_new_password_preserve_original_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let original = fs::read(&path).unwrap();
        for (old, new) in [("wrong", "new"), ("old", ""), ("old", "ows_key_new")] {
            assert!(change_wallet_passphrase("fixture", old, new, Some(directory.path())).is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        assert_eq!(
            ops::export_wallet("fixture", Some("old"), Some(directory.path())).unwrap(),
            MNEMONIC
        );
    }

    #[test]
    fn supports_initially_empty_and_unicode_passphrases() {
        let directory = tempfile::tempdir().unwrap();
        fixture(directory.path(), "", KeyType::Mnemonic);
        let new = "  café 🔒 密码  ";
        change_wallet_passphrase("wallet-id", "", new, Some(directory.path())).unwrap();
        assert_eq!(
            ops::export_wallet("fixture", Some(new), Some(directory.path())).unwrap(),
            MNEMONIC
        );
        assert!(ops::export_wallet("fixture", None, Some(directory.path())).is_err());
    }

    #[test]
    fn invalid_or_unsupported_envelopes_leave_wallet_bytes_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let original: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for (pointer, value) in [
            ("/crypto/cipher", serde_json::json!("unsupported")),
            ("/crypto/kdf", serde_json::json!("unsupported")),
            ("/crypto/cipherparams/iv", serde_json::json!("00")),
            ("/crypto/cipherparams/iv", serde_json::json!("not-hex")),
            ("/crypto/auth_tag", serde_json::json!("00")),
            ("/crypto/ciphertext", serde_json::json!("not-hex")),
            ("/crypto/kdfparams/n", serde_json::json!(3)),
            ("/crypto/kdfparams/r", serde_json::json!(0)),
            ("/crypto/kdfparams/p", serde_json::json!(0)),
            ("/crypto/kdfparams/dklen", serde_json::json!(64)),
            ("/crypto/kdfparams", serde_json::json!({})),
        ] {
            let mut document = original.clone();
            *document.pointer_mut(pointer).unwrap() = value;
            let bytes = serde_json::to_vec(&document).unwrap();
            fs::write(&path, &bytes).unwrap();
            assert!(
                change_wallet_passphrase("fixture", "old", "new", Some(directory.path())).is_err(),
                "accepted invalid envelope at {pointer}"
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let mut document = original;
        document["crypto"] = serde_json::to_value(
            ows_signer::crypto::encrypt_with_hkdf(b"fixture", "ows_key_fixture").unwrap(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&document).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(change_wallet_passphrase(
            "fixture",
            "ows_key_fixture",
            "new",
            Some(directory.path())
        )
        .is_err());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn lock_contention_and_changed_snapshot_do_not_overwrite_wallet() {
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let original = fs::read(&path).unwrap();
        let lock = lock_wallet(&path).unwrap();
        assert!(
            change_wallet_passphrase("fixture", "old", "new", Some(directory.path()))
                .unwrap_err()
                .to_string()
                .contains("in progress")
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        drop(lock);
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["metadata"] = serde_json::json!({"concurrent":"update"});
        let changed_bytes = serde_json::to_vec(&changed).unwrap();
        fs::write(&path, &changed_bytes).unwrap();
        assert!(replace_wallet_file(&path, &original, &changed)
            .unwrap_err()
            .to_string()
            .contains("wallet changed"));
        assert_eq!(fs::read(&path).unwrap(), changed_bytes);
        change_wallet_passphrase("fixture", "old", "new", Some(directory.path())).unwrap();
    }

    #[test]
    fn read_only_wallet_failure_keeps_original_usable() {
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let original = fs::read(&path).unwrap();
        let original_permissions = fs::metadata(&path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(change_wallet_passphrase("fixture", "old", "new", Some(directory.path())).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::set_permissions(&path, original_permissions).unwrap();
        assert_eq!(
            ops::export_wallet("fixture", Some("old"), Some(directory.path())).unwrap(),
            MNEMONIC
        );
    }

    #[test]
    #[cfg(unix)]
    fn read_only_vault_is_not_made_writable() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = change_wallet_passphrase("fixture", "old", "new", Some(directory.path()));
        let mode = fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
        assert_eq!(mode, 0o500);
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn preserves_legacy_wallet_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        document.as_object_mut().unwrap().remove("ows_version");
        document["lws_version"] = 1.into();
        document["chain_type"] = "evm".into();
        fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        change_wallet_passphrase("fixture", "old", "new", Some(directory.path())).unwrap();
        let changed: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(changed["lws_version"], 1);
        assert_eq!(changed["chain_type"], "evm");
        assert!(changed.get("ows_version").is_none());
    }

    #[test]
    fn missing_and_ambiguous_wallets_do_not_create_or_change_data() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent");
        assert!(matches!(
            change_wallet_passphrase("missing", "old", "new", Some(&absent)),
            Err(OwsLibError::WalletNotFound(_))
        ));
        assert!(!absent.exists());
        let path = fixture(directory.path(), "old", KeyType::Mnemonic);
        let mut duplicate: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        duplicate["id"] = "other-id".into();
        fs::write(
            directory.path().join("wallets/other-id.json"),
            serde_json::to_vec(&duplicate).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            change_wallet_passphrase("fixture", "old", "new", Some(directory.path())),
            Err(OwsLibError::AmbiguousWallet { .. })
        ));
        change_wallet_passphrase("wallet-id", "old", "new", Some(directory.path())).unwrap();
    }

    #[test]
    fn signing_and_existing_api_key_policies_survive_password_change() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Some(directory.path());
        let wallet =
            ops::import_wallet_mnemonic("agent-wallet", MNEMONIC, Some("old"), None, vault)
                .unwrap();
        let policy = Policy {
            id: "base-only".into(),
            name: "Base".into(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".into()],
            }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };
        policy_store::save_policy(&policy, vault).unwrap();
        let (token, key) = key_ops::create_api_key(
            "agent",
            std::slice::from_ref(&wallet.id),
            &[policy.id],
            "old",
            None,
            vault,
        )
        .unwrap();
        let before_key =
            serde_json::to_value(key_store::load_api_key(&key.id, vault).unwrap()).unwrap();
        let before = ops::sign_message(
            &wallet.id,
            "base",
            "offline",
            Some("old"),
            None,
            None,
            None,
            vault,
        )
        .unwrap();
        let info = change_wallet_passphrase(&wallet.id, "old", "new", vault).unwrap();
        assert_eq!(
            serde_json::to_value(info).unwrap(),
            serde_json::to_value(wallet).unwrap()
        );
        assert!(ops::sign_message(
            "agent-wallet",
            "base",
            "offline",
            Some("old"),
            None,
            None,
            None,
            vault
        )
        .is_err());
        let after = ops::sign_message(
            "agent-wallet",
            "base",
            "offline",
            Some("new"),
            None,
            None,
            None,
            vault,
        )
        .unwrap();
        assert_eq!(before.signature, after.signature);
        assert!(ops::sign_message(
            "agent-wallet",
            "base",
            "offline",
            Some(&token),
            None,
            None,
            None,
            vault
        )
        .is_ok());
        assert!(ops::sign_message(
            "agent-wallet",
            "ethereum",
            "offline",
            Some(&token),
            None,
            None,
            None,
            vault
        )
        .is_err());
        assert_eq!(
            before_key,
            serde_json::to_value(key_store::load_api_key(&key.id, vault).unwrap()).unwrap()
        );
    }
}
