use std::path::Path;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::CliError;

#[cfg_attr(test, allow(dead_code))]
const SERVICE: &str = "ows-cli-passphrase-cache";

fn cache_key(vault_path: Option<&Path>) -> String {
    let resolved = ows_lib::vault::resolve_vault_path(vault_path);
    let canonical = resolved.canonicalize().unwrap_or(resolved);
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    format!("vault-passphrase:v1:{}", hex::encode(&digest[..8]))
}

pub fn store(passphrase: &str, vault_path: Option<&Path>) -> Result<(), CliError> {
    write_secret(&cache_key(vault_path), passphrase)
}

pub fn load(vault_path: Option<&Path>) -> Result<Option<Zeroizing<String>>, CliError> {
    read_secret(&cache_key(vault_path))
}

pub fn delete(vault_path: Option<&Path>) -> Result<bool, CliError> {
    delete_secret(&cache_key(vault_path))
}

pub fn status(vault_path: Option<&Path>) -> Result<bool, CliError> {
    Ok(load(vault_path)?.is_some())
}

#[cfg(not(test))]
fn entry_for(key: &str) -> Result<keyring::Entry, CliError> {
    keyring::Entry::new(SERVICE, key).map_err(|e| CliError::PassphraseCache(e.to_string()))
}

#[cfg(not(test))]
fn write_secret(key: &str, passphrase: &str) -> Result<(), CliError> {
    entry_for(key)?
        .set_password(passphrase)
        .map_err(|e| CliError::PassphraseCache(e.to_string()))
}

#[cfg(not(test))]
fn read_secret(key: &str) -> Result<Option<Zeroizing<String>>, CliError> {
    match entry_for(key)?.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(CliError::PassphraseCache(e.to_string())),
    }
}

#[cfg(not(test))]
fn delete_secret(key: &str) -> Result<bool, CliError> {
    match entry_for(key)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(CliError::PassphraseCache(e.to_string())),
    }
}

#[cfg(test)]
fn write_secret(key: &str, passphrase: &str) -> Result<(), CliError> {
    let mut store = test_store()
        .lock()
        .map_err(|_| CliError::PassphraseCache("test store lock poisoned".into()))?;
    store.insert(key.to_string(), passphrase.to_string());
    Ok(())
}

#[cfg(test)]
fn read_secret(key: &str) -> Result<Option<Zeroizing<String>>, CliError> {
    let store = test_store()
        .lock()
        .map_err(|_| CliError::PassphraseCache("test store lock poisoned".into()))?;
    Ok(store.get(key).cloned().map(Zeroizing::new))
}

#[cfg(test)]
fn delete_secret(key: &str) -> Result<bool, CliError> {
    let mut store = test_store()
        .lock()
        .map_err(|_| CliError::PassphraseCache("test store lock poisoned".into()))?;
    Ok(store.remove(key).is_some())
}

#[cfg(test)]
fn test_store() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        assert!(!status(Some(&vault)).unwrap());

        store("secret-passphrase", Some(&vault)).unwrap();
        assert!(status(Some(&vault)).unwrap());

        let cached = load(Some(&vault)).unwrap().unwrap();
        assert_eq!(cached.as_str(), "secret-passphrase");

        assert!(delete(Some(&vault)).unwrap());
        assert!(!status(Some(&vault)).unwrap());
        assert!(load(Some(&vault)).unwrap().is_none());
    }

    #[test]
    fn delete_missing_entry_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        assert!(!delete(Some(&vault)).unwrap());
    }
}
