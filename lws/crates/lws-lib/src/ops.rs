use std::path::Path;
use std::process::Command;

use lws_core::{
    default_chain_for_type, ChainType, Config, EncryptedWallet, KeyType, WalletAccount,
    ALL_CHAIN_TYPES,
};
use lws_signer::{
    decrypt, encrypt, signer_for_chain, CryptoEnvelope, HdDeriver, Mnemonic, MnemonicStrength,
    SecretBytes,
};

use crate::error::LwsLibError;
use crate::types::{AccountInfo, SendResult, SignResult, WalletInfo};
use crate::vault;

/// Convert an EncryptedWallet to the binding-friendly WalletInfo.
fn wallet_to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w
            .accounts
            .iter()
            .map(|a| AccountInfo {
                chain_id: a.chain_id.clone(),
                address: a.address.clone(),
                derivation_path: a.derivation_path.clone(),
            })
            .collect(),
        created_at: w.created_at.clone(),
    }
}

fn parse_chain(s: &str) -> Result<lws_core::Chain, LwsLibError> {
    lws_core::parse_chain(s).map_err(|e| LwsLibError::InvalidInput(e))
}

/// Derive accounts for all chain families from a mnemonic at the given index.
fn derive_all_accounts(
    mnemonic: &Mnemonic,
    index: u32,
) -> Result<Vec<WalletAccount>, LwsLibError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        let signer = signer_for_chain(*ct);
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();
        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve)?;
        let address = signer.derive_address(key.expose())?;
        let account_id = format!("{}:{}", chain.chain_id, address);
        accounts.push(WalletAccount {
            account_id,
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

/// Derive accounts for all chain families from raw key bytes.
/// Skips chains whose signer doesn't support the key's curve.
fn derive_all_accounts_from_key(key_bytes: &[u8]) -> Result<Vec<WalletAccount>, LwsLibError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let signer = signer_for_chain(*ct);
        match signer.derive_address(key_bytes) {
            Ok(address) => {
                let chain = default_chain_for_type(*ct);
                accounts.push(WalletAccount {
                    account_id: format!("{}:{}", chain.chain_id, address),
                    address,
                    chain_id: chain.chain_id.to_string(),
                    derivation_path: String::new(),
                });
            }
            Err(_) => {
                // Skip chains that can't derive from this key (e.g. wrong curve)
                continue;
            }
        }
    }
    if accounts.is_empty() {
        return Err(LwsLibError::InvalidInput(
            "could not derive address for any chain from this private key".into(),
        ));
    }
    Ok(accounts)
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: u32) -> Result<String, LwsLibError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(LwsLibError::InvalidInput("words must be 12 or 24".into())),
    };

    let mnemonic = Mnemonic::generate(strength)?;
    let phrase = mnemonic.phrase();
    String::from_utf8(phrase.expose().to_vec())
        .map_err(|e| LwsLibError::InvalidInput(format!("invalid UTF-8 in mnemonic: {e}")))
}

/// Derive an address from a mnemonic phrase for the given chain.
pub fn derive_address(
    mnemonic_phrase: &str,
    chain: &str,
    index: Option<u32>,
) -> Result<String, LwsLibError> {
    let chain = parse_chain(chain)?;
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let signer = signer_for_chain(chain.chain_type);
    let path = signer.default_derivation_path(index.unwrap_or(0));
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve)?;
    let address = signer.derive_address(key.expose())?;
    Ok(address)
}

/// Create a new universal wallet: generates mnemonic, derives addresses for all chains,
/// encrypts, and saves to vault.
pub fn create_wallet(
    name: &str,
    words: Option<u32>,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let words = words.unwrap_or(12);
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(LwsLibError::InvalidInput("words must be 12 or 24".into())),
    };

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(LwsLibError::WalletNameExists(name.to_string()));
    }

    let mnemonic = Mnemonic::generate(strength)?;
    let accounts = derive_all_accounts(&mnemonic, 0)?;

    let phrase = mnemonic.phrase();
    let crypto_envelope = encrypt(phrase.expose(), passphrase)?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id,
        name.to_string(),
        accounts,
        crypto_json,
        KeyType::Mnemonic,
    );

    vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Import a wallet from a mnemonic phrase. Derives addresses for all chains.
pub fn import_wallet_mnemonic(
    name: &str,
    mnemonic_phrase: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let index = index.unwrap_or(0);

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(LwsLibError::WalletNameExists(name.to_string()));
    }

    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let accounts = derive_all_accounts(&mnemonic, index)?;

    let phrase = mnemonic.phrase();
    let crypto_envelope = encrypt(phrase.expose(), passphrase)?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id,
        name.to_string(),
        accounts,
        crypto_json,
        KeyType::Mnemonic,
    );

    vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Import a wallet from a hex-encoded private key. Derives addresses for all chains.
pub fn import_wallet_private_key(
    name: &str,
    private_key_hex: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(LwsLibError::WalletNameExists(name.to_string()));
    }

    let hex_trimmed = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
    let key_bytes = hex::decode(hex_trimmed)
        .map_err(|e| LwsLibError::InvalidInput(format!("invalid hex private key: {e}")))?;

    let accounts = derive_all_accounts_from_key(&key_bytes)?;

    let crypto_envelope = encrypt(&key_bytes, passphrase)?;
    let crypto_json = serde_json::to_value(&crypto_envelope)?;

    let wallet_id = uuid::Uuid::new_v4().to_string();

    let wallet = EncryptedWallet::new(
        wallet_id,
        name.to_string(),
        accounts,
        crypto_json,
        KeyType::PrivateKey,
    );

    vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// List all wallets in the vault.
pub fn list_wallets(vault_path: Option<&Path>) -> Result<Vec<WalletInfo>, LwsLibError> {
    let wallets = vault::list_encrypted_wallets(vault_path)?;
    Ok(wallets.iter().map(wallet_to_info).collect())
}

/// Get a single wallet by name or ID.
pub fn get_wallet(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<WalletInfo, LwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Delete a wallet from the vault.
pub fn delete_wallet(
    name_or_id: &str,
    vault_path: Option<&Path>,
) -> Result<(), LwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    vault::delete_wallet_file(&wallet.id, vault_path)?;
    Ok(())
}

/// Export a wallet's secret (mnemonic or private key hex).
pub fn export_wallet(
    name_or_id: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<String, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;

    match wallet.key_type {
        KeyType::Mnemonic => String::from_utf8(secret.expose().to_vec())
            .map_err(|_| LwsLibError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into())),
        KeyType::PrivateKey => Ok(hex::encode(secret.expose())),
    }
}

/// Rename a wallet.
pub fn rename_wallet(
    name_or_id: &str,
    new_name: &str,
    vault_path: Option<&Path>,
) -> Result<(), LwsLibError> {
    let mut wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;

    if wallet.name == new_name {
        return Ok(());
    }

    if vault::wallet_name_exists(new_name, vault_path)? {
        return Err(LwsLibError::WalletNameExists(new_name.to_string()));
    }

    wallet.name = new_name.to_string();
    vault::save_encrypted_wallet(&wallet, vault_path)?;
    Ok(())
}

/// Sign a transaction. Returns hex-encoded signature.
pub fn sign_transaction(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| LwsLibError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    let key = decrypt_signing_key(wallet, chain.chain_type, passphrase, index, vault_path)?;
    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_transaction(key.expose(), &tx_bytes)?;

    Ok(SignResult {
        signature: hex::encode(&output.signature),
        recovery_id: output.recovery_id,
    })
}

/// Sign a message. Returns hex-encoded signature.
pub fn sign_message(
    wallet: &str,
    chain: &str,
    message: &str,
    passphrase: Option<&str>,
    encoding: Option<&str>,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    let encoding = encoding.unwrap_or("utf8");
    let msg_bytes = match encoding {
        "utf8" => message.as_bytes().to_vec(),
        "hex" => hex::decode(message)
            .map_err(|e| LwsLibError::InvalidInput(format!("invalid hex message: {e}")))?,
        _ => {
            return Err(LwsLibError::InvalidInput(format!(
                "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
            )))
        }
    };

    let key = decrypt_signing_key(wallet, chain.chain_type, passphrase, index, vault_path)?;
    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_message(key.expose(), &msg_bytes)?;

    Ok(SignResult {
        signature: hex::encode(&output.signature),
        recovery_id: output.recovery_id,
    })
}

/// Sign and broadcast a transaction. Returns the transaction hash.
pub fn sign_and_send(
    wallet: &str,
    chain: &str,
    tx_hex: &str,
    passphrase: Option<&str>,
    index: Option<u32>,
    rpc_url: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<SendResult, LwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    // 1. Sign
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| LwsLibError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    let key = decrypt_signing_key(wallet, chain.chain_type, passphrase, index, vault_path)?;
    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_transaction(key.expose(), &tx_bytes)?;

    // 2. Resolve RPC URL using exact chain_id
    let rpc = resolve_rpc_url(chain.chain_id, chain.chain_type, rpc_url)?;

    // 3. Broadcast
    let tx_hash = broadcast(chain.chain_type, &rpc, &output.signature)?;

    Ok(SendResult { tx_hash })
}

// --- internal helpers ---

/// Decrypt a wallet and derive the private key for the given chain and index.
fn decrypt_signing_key(
    wallet_name_or_id: &str,
    chain_type: ChainType,
    passphrase: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, LwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;

    match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(secret.expose().to_vec())
                .map_err(|_| LwsLibError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into()))?;
            let mnemonic = Mnemonic::from_phrase(&phrase)?;
            let signer = signer_for_chain(chain_type);
            let path = signer.default_derivation_path(index.unwrap_or(0));
            let curve = signer.curve();
            Ok(HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve)?)
        }
        KeyType::PrivateKey => {
            // Raw key bytes — use directly (index is ignored)
            Ok(secret)
        }
    }
}

/// Resolve the RPC URL: explicit > config override (exact chain_id) > config (namespace) > built-in default.
fn resolve_rpc_url(
    chain_id: &str,
    chain_type: ChainType,
    explicit: Option<&str>,
) -> Result<String, LwsLibError> {
    if let Some(url) = explicit {
        return Ok(url.to_string());
    }

    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    // Try exact chain_id match first
    if let Some(url) = config.rpc.get(chain_id) {
        return Ok(url.clone());
    }
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }

    // Fallback to namespace match
    let namespace = chain_type.namespace();
    for (key, url) in &config.rpc {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }
    for (key, url) in &defaults {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }

    Err(LwsLibError::InvalidInput(format!(
        "no RPC URL configured for chain '{chain_id}'"
    )))
}

/// Broadcast a signed transaction via curl, dispatching per chain type.
fn broadcast(chain: ChainType, rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    match chain {
        ChainType::Evm => broadcast_evm(rpc_url, signed_bytes),
        ChainType::Solana => broadcast_solana(rpc_url, signed_bytes),
        ChainType::Bitcoin => broadcast_bitcoin(rpc_url, signed_bytes),
        ChainType::Cosmos => broadcast_cosmos(rpc_url, signed_bytes),
        ChainType::Tron => broadcast_tron(rpc_url, signed_bytes),
        ChainType::Ton => broadcast_ton(rpc_url, signed_bytes),
    }
}

fn broadcast_evm(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    let hex_tx = format!("0x{}", hex::encode(signed_bytes));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [hex_tx],
        "id": 1
    });
    let resp = curl_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

fn broadcast_solana(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sendTransaction",
        "params": [b64_tx],
        "id": 1
    });
    let resp = curl_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

fn broadcast_bitcoin(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X", "POST",
            "-H", "Content-Type: text/plain",
            "-d", &hex_tx,
            &url,
        ])
        .output()
        .map_err(|e| LwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LwsLibError::BroadcastFailed(format!("broadcast failed: {stderr}")));
    }

    let tx_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tx_hash.is_empty() {
        return Err(LwsLibError::BroadcastFailed("empty response from broadcast".into()));
    }
    Ok(tx_hash)
}

fn broadcast_cosmos(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!(
        "{}/cosmos/tx/v1beta1/txs",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "tx_bytes": b64_tx,
        "mode": "BROADCAST_MODE_SYNC"
    });
    let resp = curl_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["tx_response"]["txhash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| LwsLibError::BroadcastFailed(format!("no txhash in response: {resp}")))
}

fn broadcast_tron(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!(
        "{}/wallet/broadcasthex",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "transaction": hex_tx });
    let resp = curl_post_json(&url, &body.to_string())?;
    extract_json_field(&resp, "txid")
}

fn broadcast_ton(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, LwsLibError> {
    use base64::Engine;
    let b64_boc = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!(
        "{}/sendBoc",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "boc": b64_boc });
    let resp = curl_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["result"]["hash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| LwsLibError::BroadcastFailed(format!("no hash in response: {resp}")))
}

fn curl_post_json(url: &str, body: &str) -> Result<String, LwsLibError> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", body,
            url,
        ])
        .output()
        .map_err(|e| LwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(LwsLibError::BroadcastFailed(format!("broadcast failed: {stderr}")));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn extract_json_field(json_str: &str, field: &str) -> Result<String, LwsLibError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;

    if let Some(error) = parsed.get("error") {
        return Err(LwsLibError::BroadcastFailed(format!("RPC error: {error}")));
    }

    parsed[field]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| LwsLibError::BroadcastFailed(format!("no '{field}' in response: {json_str}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24() {
        let phrase = generate_mnemonic(24).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn test_generate_mnemonic_invalid() {
        assert!(generate_mnemonic(15).is_err());
    }

    #[test]
    fn test_derive_address_evm() {
        let phrase = generate_mnemonic(12).unwrap();
        let addr = derive_address(&phrase, "evm", None).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_derive_address_ethereum() {
        let phrase = generate_mnemonic(12).unwrap();
        let addr = derive_address(&phrase, "ethereum", None).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
    }

    #[test]
    fn test_derive_address_solana() {
        let phrase = generate_mnemonic(12).unwrap();
        let addr = derive_address(&phrase, "solana", None).unwrap();
        assert!(!addr.is_empty());
    }

    #[test]
    fn test_create_universal_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("test-wallet", None, None, Some(vault)).unwrap();

        assert_eq!(info.name, "test-wallet");
        assert_eq!(info.accounts.len(), 6, "universal wallet should have 6 accounts");

        // Verify each chain family is present
        let chain_ids: Vec<&str> = info.accounts.iter().map(|a| a.chain_id.as_str()).collect();
        assert!(chain_ids.iter().any(|c| c.starts_with("eip155:")));
        assert!(chain_ids.iter().any(|c| c.starts_with("solana:")));
        assert!(chain_ids.iter().any(|c| c.starts_with("bip122:")));
        assert!(chain_ids.iter().any(|c| c.starts_with("cosmos:")));
        assert!(chain_ids.iter().any(|c| c.starts_with("tron:")));
        assert!(chain_ids.iter().any(|c| c.starts_with("ton:")));

        let wallets = list_wallets(Some(vault)).unwrap();
        assert_eq!(wallets.len(), 1);
        assert_eq!(wallets[0].id, info.id);
    }

    #[test]
    fn test_create_wallet_duplicate_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("dup-name", None, None, Some(vault)).unwrap();
        let err = create_wallet("dup-name", None, None, Some(vault));
        assert!(err.is_err());
    }

    #[test]
    fn test_get_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("lookup-test", None, None, Some(vault)).unwrap();

        // By name
        let found = get_wallet("lookup-test", Some(vault)).unwrap();
        assert_eq!(found.id, info.id);

        // By ID
        let found = get_wallet(&info.id, Some(vault)).unwrap();
        assert_eq!(found.name, "lookup-test");
    }

    #[test]
    fn test_delete_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("del-test", None, None, Some(vault)).unwrap();

        delete_wallet(&info.id, Some(vault)).unwrap();
        assert!(list_wallets(Some(vault)).unwrap().is_empty());
    }

    #[test]
    fn test_export_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("export-test", None, None, Some(vault)).unwrap();

        let secret = export_wallet("export-test", None, Some(vault)).unwrap();
        // The secret should be a valid mnemonic (12 words)
        assert_eq!(secret.split_whitespace().count(), 12);
    }

    #[test]
    fn test_rename_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("old-name", None, None, Some(vault)).unwrap();
        rename_wallet("old-name", "new-name", Some(vault)).unwrap();

        let found = get_wallet("new-name", Some(vault)).unwrap();
        assert_eq!(found.name, "new-name");
        assert!(get_wallet("old-name", Some(vault)).is_err());
    }

    #[test]
    fn test_import_wallet_mnemonic() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let phrase = generate_mnemonic(12).unwrap();
        let expected_evm_addr = derive_address(&phrase, "ethereum", None).unwrap();

        let info = import_wallet_mnemonic(
            "imported",
            &phrase,
            None,
            None,
            Some(vault),
        )
        .unwrap();

        assert_eq!(info.name, "imported");
        assert_eq!(info.accounts.len(), 6);

        // The EVM account should match the derived address
        let evm_account = info.accounts.iter().find(|a| a.chain_id.starts_with("eip155:")).unwrap();
        assert_eq!(evm_account.address, expected_evm_addr);
    }

    #[test]
    fn test_sign_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("signer", None, None, Some(vault)).unwrap();

        let tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let result =
            sign_transaction("signer", "evm", tx_hex, None, None, Some(vault))
                .unwrap();

        assert!(!result.signature.is_empty());
        assert!(result.recovery_id.is_some());
    }

    #[test]
    fn test_sign_message() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("msg-signer", None, None, Some(vault)).unwrap();

        let result = sign_message(
            "msg-signer",
            "evm",
            "hello world",
            None,
            None,
            None,
            Some(vault),
        )
        .unwrap();

        assert!(!result.signature.is_empty());
    }

    #[test]
    fn test_universal_wallet_addresses_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let phrase = generate_mnemonic(12).unwrap();

        let info = import_wallet_mnemonic("deterministic", &phrase, None, None, Some(vault)).unwrap();

        // Derive each address individually and verify they match
        for acct in &info.accounts {
            let chain_str = if acct.chain_id.starts_with("eip155:") {
                "ethereum"
            } else if acct.chain_id.starts_with("solana:") {
                "solana"
            } else if acct.chain_id.starts_with("bip122:") {
                "bitcoin"
            } else if acct.chain_id.starts_with("cosmos:") {
                "cosmos"
            } else if acct.chain_id.starts_with("tron:") {
                "tron"
            } else if acct.chain_id.starts_with("ton:") {
                "ton"
            } else {
                panic!("unknown chain_id: {}", acct.chain_id);
            };

            let derived = derive_address(&phrase, chain_str, None).unwrap();
            assert_eq!(acct.address, derived, "address mismatch for {}", chain_str);
        }
    }

    #[test]
    fn test_addresses_computationally_related() {
        // Verify that all addresses in a universal wallet are derived from the
        // same mnemonic seed, and that re-importing the same mnemonic produces
        // identical addresses across all chains.
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();

        // Create a wallet and export its mnemonic
        let info1 = create_wallet("wallet-a", None, None, Some(dir1.path())).unwrap();
        let mnemonic = export_wallet("wallet-a", None, Some(dir1.path())).unwrap();

        // Import the same mnemonic into a second vault
        let info2 = import_wallet_mnemonic("wallet-b", &mnemonic, None, None, Some(dir2.path())).unwrap();

        // All 6 accounts must match exactly (same mnemonic → same addresses)
        assert_eq!(info1.accounts.len(), 6);
        assert_eq!(info2.accounts.len(), 6);
        for (a1, a2) in info1.accounts.iter().zip(info2.accounts.iter()) {
            assert_eq!(a1.chain_id, a2.chain_id, "chain_id mismatch");
            assert_eq!(a1.address, a2.address,
                "address mismatch for {}: created={} vs imported={}",
                a1.chain_id, a1.address, a2.address
            );
            assert_eq!(a1.derivation_path, a2.derivation_path, "derivation_path mismatch");
        }

        // Verify the addresses are all distinct from each other
        // (different chains produce different addresses from the same seed)
        let addresses: Vec<&str> = info1.accounts.iter().map(|a| a.address.as_str()).collect();
        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                assert_ne!(addresses[i], addresses[j],
                    "addresses for {} and {} should differ",
                    info1.accounts[i].chain_id, info1.accounts[j].chain_id
                );
            }
        }

        // Verify each address individually matches derive_address()
        for acct in &info1.accounts {
            let chain_str = if acct.chain_id.starts_with("eip155:") {
                "ethereum"
            } else if acct.chain_id.starts_with("solana:") {
                "solana"
            } else if acct.chain_id.starts_with("bip122:") {
                "bitcoin"
            } else if acct.chain_id.starts_with("cosmos:") {
                "cosmos"
            } else if acct.chain_id.starts_with("tron:") {
                "tron"
            } else {
                "ton"
            };
            let derived = derive_address(&mnemonic, chain_str, None).unwrap();
            assert_eq!(acct.address, derived,
                "derive_address mismatch for {}", chain_str);
        }
    }

    #[test]
    fn test_import_private_key_sign_and_export() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        // A known 32-byte secp256k1 private key (hex)
        let privkey_hex = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let key_bytes = hex::decode(privkey_hex).unwrap();

        // Manually build a wallet with only EVM account (avoids TON panic)
        let signer = signer_for_chain(ChainType::Evm);
        let address = signer.derive_address(&key_bytes).unwrap();
        let chain = default_chain_for_type(ChainType::Evm);
        let accounts = vec![WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: String::new(),
        }];

        let crypto_envelope = encrypt(&key_bytes, "").unwrap();
        let crypto_json = serde_json::to_value(&crypto_envelope).unwrap();
        let wallet_id = uuid::Uuid::new_v4().to_string();
        let wallet = EncryptedWallet::new(
            wallet_id,
            "pk-wallet".to_string(),
            accounts,
            crypto_json,
            KeyType::PrivateKey,
        );
        vault::save_encrypted_wallet(&wallet, Some(vault)).unwrap();

        // Sign a message — this was the bug: "wallet contains invalid UTF-8 secret"
        let sig = sign_message("pk-wallet", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Sign a transaction
        let tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("pk-wallet", "evm", tx_hex, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Export — should return hex-encoded key, not blow up with UTF-8 error
        let exported = export_wallet("pk-wallet", None, Some(vault)).unwrap();
        assert_eq!(exported, privkey_hex);

        delete_wallet("pk-wallet", Some(vault)).unwrap();
    }
}
