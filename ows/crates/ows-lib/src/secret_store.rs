use std::path::Path;

use ows_core::KeyType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::OwsLibError;

const SERVICE: &str = "ows";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretRecord {
    version: u32,
    wallet_id: String,
    key_type: KeyType,
    payload: String,
}

pub fn secret_ref_for_wallet(wallet_id: &str, vault_path: Option<&Path>) -> String {
    let vault = crate::vault::resolve_vault_path(vault_path);
    let digest = Sha256::digest(vault.to_string_lossy().as_bytes());
    let scope = hex::encode(&digest[..8]);
    format!("wallet:v1:{scope}:{wallet_id}")
}

pub fn store_wallet_secret(
    secret_ref: &str,
    wallet_id: &str,
    key_type: KeyType,
    payload: &str,
) -> Result<(), OwsLibError> {
    let record = SecretRecord {
        version: 1,
        wallet_id: wallet_id.to_string(),
        key_type,
        payload: payload.to_string(),
    };
    let serialized = Zeroizing::new(
        serde_json::to_string(&record)
            .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))?,
    );
    write_secret(secret_ref, &serialized)
}

pub fn load_wallet_secret(secret_ref: &str) -> Result<Zeroizing<String>, OwsLibError> {
    let serialized = read_secret(secret_ref)?;
    let record: SecretRecord = serde_json::from_str(&serialized)
        .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))?;
    Ok(Zeroizing::new(record.payload))
}

pub fn delete_wallet_secret(secret_ref: &str) -> Result<(), OwsLibError> {
    delete_secret(secret_ref)
}

#[cfg(not(test))]
fn write_secret(secret_ref: &str, serialized: &str) -> Result<(), OwsLibError> {
    let entry = keyring::Entry::new(SERVICE, secret_ref)
        .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))?;
    entry
        .set_password(serialized)
        .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))
}

#[cfg(not(test))]
fn read_secret(secret_ref: &str) -> Result<Zeroizing<String>, OwsLibError> {
    let entry = keyring::Entry::new(SERVICE, secret_ref)
        .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))?;
    match entry.get_password() {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(keyring::Error::NoEntry) => Err(OwsLibError::SecretNotFound(secret_ref.to_string())),
        Err(e) => Err(OwsLibError::SecretStoreUnavailable(e.to_string())),
    }
}

#[cfg(not(test))]
fn delete_secret(secret_ref: &str) -> Result<(), OwsLibError> {
    let entry = keyring::Entry::new(SERVICE, secret_ref)
        .map_err(|e| OwsLibError::SecretStoreUnavailable(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(OwsLibError::SecretStoreUnavailable(e.to_string())),
    }
}

#[cfg(test)]
fn write_secret(secret_ref: &str, serialized: &str) -> Result<(), OwsLibError> {
    let mut store = test_store()
        .lock()
        .map_err(|_| OwsLibError::SecretStoreUnavailable("test store lock poisoned".into()))?;
    store.insert(secret_ref.to_string(), serialized.to_string());
    Ok(())
}

#[cfg(test)]
fn read_secret(secret_ref: &str) -> Result<Zeroizing<String>, OwsLibError> {
    let store = test_store()
        .lock()
        .map_err(|_| OwsLibError::SecretStoreUnavailable("test store lock poisoned".into()))?;
    let value = store
        .get(secret_ref)
        .cloned()
        .ok_or_else(|| OwsLibError::SecretNotFound(secret_ref.to_string()))?;
    Ok(Zeroizing::new(value))
}

#[cfg(test)]
fn delete_secret(secret_ref: &str) -> Result<(), OwsLibError> {
    let mut store = test_store()
        .lock()
        .map_err(|_| OwsLibError::SecretStoreUnavailable("test store lock poisoned".into()))?;
    store.remove(secret_ref);
    Ok(())
}

#[cfg(test)]
fn test_store() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static STORE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

