use std::path::Path;
use std::process::Command;

use ows_core::{
    default_chain_for_type, ChainType, Config, EncryptedWallet, KeyType, WalletAccount,
    ALL_CHAIN_TYPES,
};
use ows_signer::{
    decrypt, encrypt, signer_for_chain, CryptoEnvelope, HdDeriver, Mnemonic, MnemonicStrength,
    SecretBytes,
};

use crate::error::OwsLibError;
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

fn parse_chain(s: &str) -> Result<ows_core::Chain, OwsLibError> {
    ows_core::parse_chain(s).map_err(OwsLibError::InvalidInput)
}

/// Derive accounts for all chain families from a mnemonic at the given index.
fn derive_all_accounts(mnemonic: &Mnemonic, index: u32) -> Result<Vec<WalletAccount>, OwsLibError> {
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

/// A key pair: one key per curve.
/// Private key material is zeroized on drop.
struct KeyPair {
    secp256k1: Vec<u8>,
    ed25519: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secp256k1.zeroize();
        self.ed25519.zeroize();
    }
}

impl KeyPair {
    /// Get the key for a given curve.
    fn key_for_curve(&self, curve: ows_signer::Curve) -> &[u8] {
        match curve {
            ows_signer::Curve::Secp256k1 => &self.secp256k1,
            ows_signer::Curve::Ed25519 => &self.ed25519,
        }
    }

    /// Serialize to JSON bytes for encryption.
    fn to_json_bytes(&self) -> Vec<u8> {
        let obj = serde_json::json!({
            "secp256k1": hex::encode(&self.secp256k1),
            "ed25519": hex::encode(&self.ed25519),
        });
        obj.to_string().into_bytes()
    }

    /// Deserialize from JSON bytes after decryption.
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, OwsLibError> {
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|_| OwsLibError::InvalidInput("invalid key pair data".into()))?;
        let obj: serde_json::Value = serde_json::from_str(&s)?;
        let secp = obj["secp256k1"]
            .as_str()
            .ok_or_else(|| OwsLibError::InvalidInput("missing secp256k1 key".into()))?;
        let ed = obj["ed25519"]
            .as_str()
            .ok_or_else(|| OwsLibError::InvalidInput("missing ed25519 key".into()))?;
        Ok(KeyPair {
            secp256k1: hex::decode(secp)
                .map_err(|e| OwsLibError::InvalidInput(format!("invalid secp256k1 hex: {e}")))?,
            ed25519: hex::decode(ed)
                .map_err(|e| OwsLibError::InvalidInput(format!("invalid ed25519 hex: {e}")))?,
        })
    }
}

/// Derive accounts for all chain families using a key pair (one key per curve).
fn derive_all_accounts_from_keys(keys: &KeyPair) -> Result<Vec<WalletAccount>, OwsLibError> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let signer = signer_for_chain(*ct);
        let key = keys.key_for_curve(signer.curve());
        let address = signer.derive_address(key)?;
        let chain = default_chain_for_type(*ct);
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: String::new(),
        });
    }
    Ok(accounts)
}

/// Generate a new BIP-39 mnemonic phrase.
pub fn generate_mnemonic(words: u32) -> Result<String, OwsLibError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(OwsLibError::InvalidInput("words must be 12 or 24".into())),
    };

    let mnemonic = Mnemonic::generate(strength)?;
    let phrase = mnemonic.phrase();
    String::from_utf8(phrase.expose().to_vec())
        .map_err(|e| OwsLibError::InvalidInput(format!("invalid UTF-8 in mnemonic: {e}")))
}

/// Derive an address from a mnemonic phrase for the given chain.
pub fn derive_address(
    mnemonic_phrase: &str,
    chain: &str,
    index: Option<u32>,
) -> Result<String, OwsLibError> {
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
) -> Result<WalletInfo, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let words = words.unwrap_or(12);
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(OwsLibError::InvalidInput("words must be 12 or 24".into())),
    };

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(OwsLibError::WalletNameExists(name.to_string()));
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
) -> Result<WalletInfo, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let index = index.unwrap_or(0);

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(OwsLibError::WalletNameExists(name.to_string()));
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

/// Decode a hex-encoded key, stripping an optional `0x` prefix.
fn decode_hex_key(hex_str: &str) -> Result<Vec<u8>, OwsLibError> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed)
        .map_err(|e| OwsLibError::InvalidInput(format!("invalid hex private key: {e}")))
}

/// Import a wallet from a hex-encoded private key.
/// The `chain` parameter specifies which chain the key originates from (e.g. "evm", "solana").
/// A random key is generated for the other curve so all 6 chains are supported.
///
/// Alternatively, provide both `secp256k1_key_hex` and `ed25519_key_hex` to supply
/// explicit keys for each curve. When both are given, `private_key_hex` and `chain`
/// are ignored. When only one curve key is given alongside `private_key_hex`, it
/// overrides the random generation for that curve.
pub fn import_wallet_private_key(
    name: &str,
    private_key_hex: &str,
    chain: Option<&str>,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
    secp256k1_key_hex: Option<&str>,
    ed25519_key_hex: Option<&str>,
) -> Result<WalletInfo, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");

    if vault::wallet_name_exists(name, vault_path)? {
        return Err(OwsLibError::WalletNameExists(name.to_string()));
    }

    let keys = match (secp256k1_key_hex, ed25519_key_hex) {
        // Both curve keys explicitly provided — use them directly
        (Some(secp_hex), Some(ed_hex)) => KeyPair {
            secp256k1: decode_hex_key(secp_hex)?,
            ed25519: decode_hex_key(ed_hex)?,
        },
        // Existing single-key behavior
        _ => {
            let key_bytes = decode_hex_key(private_key_hex)?;

            // Determine curve from the source chain (default: secp256k1)
            let source_curve = match chain {
                Some(c) => {
                    let parsed = parse_chain(c)?;
                    signer_for_chain(parsed.chain_type).curve()
                }
                None => ows_signer::Curve::Secp256k1,
            };

            // Build key pair: provided key for its curve, random 32 bytes for the other
            let mut other_key = vec![0u8; 32];
            getrandom::getrandom(&mut other_key).map_err(|e| {
                OwsLibError::InvalidInput(format!("failed to generate random key: {e}"))
            })?;

            match source_curve {
                ows_signer::Curve::Secp256k1 => KeyPair {
                    secp256k1: key_bytes,
                    ed25519: ed25519_key_hex
                        .map(decode_hex_key)
                        .transpose()?
                        .unwrap_or(other_key),
                },
                ows_signer::Curve::Ed25519 => KeyPair {
                    secp256k1: secp256k1_key_hex
                        .map(decode_hex_key)
                        .transpose()?
                        .unwrap_or(other_key),
                    ed25519: key_bytes,
                },
            }
        }
    };

    let accounts = derive_all_accounts_from_keys(&keys)?;

    let payload = keys.to_json_bytes();
    let crypto_envelope = encrypt(&payload, passphrase)?;
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
pub fn list_wallets(vault_path: Option<&Path>) -> Result<Vec<WalletInfo>, OwsLibError> {
    let wallets = vault::list_encrypted_wallets(vault_path)?;
    Ok(wallets.iter().map(wallet_to_info).collect())
}

/// Get a single wallet by name or ID.
pub fn get_wallet(name_or_id: &str, vault_path: Option<&Path>) -> Result<WalletInfo, OwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    Ok(wallet_to_info(&wallet))
}

/// Delete a wallet from the vault.
pub fn delete_wallet(name_or_id: &str, vault_path: Option<&Path>) -> Result<(), OwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    vault::delete_wallet_file(&wallet.id, vault_path)?;
    Ok(())
}

/// Export a wallet's secret.
/// Mnemonic wallets return the phrase. Private key wallets return JSON with both keys.
pub fn export_wallet(
    name_or_id: &str,
    passphrase: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<String, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;

    match wallet.key_type {
        KeyType::Mnemonic => String::from_utf8(secret.expose().to_vec()).map_err(|_| {
            OwsLibError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into())
        }),
        KeyType::PrivateKey => {
            // Return the JSON key pair as-is
            String::from_utf8(secret.expose().to_vec())
                .map_err(|_| OwsLibError::InvalidInput("wallet contains invalid key data".into()))
        }
    }
}

/// Rename a wallet.
pub fn rename_wallet(
    name_or_id: &str,
    new_name: &str,
    vault_path: Option<&Path>,
) -> Result<(), OwsLibError> {
    let mut wallet = vault::load_wallet_by_name_or_id(name_or_id, vault_path)?;

    if wallet.name == new_name {
        return Ok(());
    }

    if vault::wallet_name_exists(new_name, vault_path)? {
        return Err(OwsLibError::WalletNameExists(new_name.to_string()));
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
) -> Result<SignResult, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwsLibError::InvalidInput(format!("invalid hex transaction: {e}")))?;

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
) -> Result<SignResult, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain = parse_chain(chain)?;

    let encoding = encoding.unwrap_or("utf8");
    let msg_bytes = match encoding {
        "utf8" => message.as_bytes().to_vec(),
        "hex" => hex::decode(message)
            .map_err(|e| OwsLibError::InvalidInput(format!("invalid hex message: {e}")))?,
        _ => {
            return Err(OwsLibError::InvalidInput(format!(
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
) -> Result<SendResult, OwsLibError> {
    let passphrase = passphrase.unwrap_or("");
    let chain_info = parse_chain(chain)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| OwsLibError::InvalidInput(format!("invalid hex transaction: {e}")))?;

    let key = decrypt_signing_key(wallet, chain_info.chain_type, passphrase, index, vault_path)?;

    sign_encode_and_broadcast(key.expose(), chain, &tx_bytes, rpc_url)
}

/// Sign, encode, and broadcast a transaction using an already-resolved private key.
///
/// This is the shared core of the send-transaction flow. Both the library's
/// [`sign_and_send`] (which resolves keys from the vault) and the CLI (which
/// resolves keys via env vars / stdin prompts) delegate here so the
/// sign → encode → broadcast pipeline is never duplicated.
pub fn sign_encode_and_broadcast(
    private_key: &[u8],
    chain: &str,
    tx_bytes: &[u8],
    rpc_url: Option<&str>,
) -> Result<SendResult, OwsLibError> {
    let chain = parse_chain(chain)?;
    let signer = signer_for_chain(chain.chain_type);

    // 1. Extract signable portion (strips signature-slot headers for Solana; no-op for others)
    let signable = signer.extract_signable_bytes(tx_bytes)?;

    // 2. Sign
    let output = signer.sign_transaction(private_key, signable)?;

    // 3. Encode the full signed transaction
    let signed_tx = signer.encode_signed_transaction(tx_bytes, &output)?;

    // 4. Resolve RPC URL using exact chain_id
    let rpc = resolve_rpc_url(chain.chain_id, chain.chain_type, rpc_url)?;

    // 5. Broadcast the full signed transaction
    let tx_hash = broadcast(chain.chain_type, &rpc, &signed_tx)?;

    Ok(SendResult { tx_hash })
}

// --- internal helpers ---

/// Decrypt a wallet and return the private key for the given chain.
fn decrypt_signing_key(
    wallet_name_or_id: &str,
    chain_type: ChainType,
    passphrase: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SecretBytes, OwsLibError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase)?;

    match wallet.key_type {
        KeyType::Mnemonic => {
            // Use the SecretBytes directly as a &str to avoid un-zeroized String copies.
            let phrase = std::str::from_utf8(secret.expose()).map_err(|_| {
                OwsLibError::InvalidInput("wallet contains invalid UTF-8 mnemonic".into())
            })?;
            let mnemonic = Mnemonic::from_phrase(phrase)?;
            let signer = signer_for_chain(chain_type);
            let path = signer.default_derivation_path(index.unwrap_or(0));
            let curve = signer.curve();
            Ok(HdDeriver::derive_from_mnemonic(
                &mnemonic, "", &path, curve,
            )?)
        }
        KeyType::PrivateKey => {
            // JSON key pair — extract the right key for this chain's curve
            let keys = KeyPair::from_json_bytes(secret.expose())?;
            let signer = signer_for_chain(chain_type);
            Ok(SecretBytes::from_slice(keys.key_for_curve(signer.curve())))
        }
    }
}

/// Resolve the RPC URL: explicit > config override (exact chain_id) > config (namespace) > built-in default.
fn resolve_rpc_url(
    chain_id: &str,
    chain_type: ChainType,
    explicit: Option<&str>,
) -> Result<String, OwsLibError> {
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

    Err(OwsLibError::InvalidInput(format!(
        "no RPC URL configured for chain '{chain_id}'"
    )))
}

/// Broadcast a signed transaction via curl, dispatching per chain type.
fn broadcast(chain: ChainType, rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    match chain {
        ChainType::Evm => broadcast_evm(rpc_url, signed_bytes),
        ChainType::Solana => broadcast_solana(rpc_url, signed_bytes),
        ChainType::Bitcoin => broadcast_bitcoin(rpc_url, signed_bytes),
        ChainType::Cosmos => broadcast_cosmos(rpc_url, signed_bytes),
        ChainType::Tron => broadcast_tron(rpc_url, signed_bytes),
        ChainType::Ton => broadcast_ton(rpc_url, signed_bytes),
    }
}

fn broadcast_evm(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
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

fn broadcast_solana(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
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

fn broadcast_bitcoin(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X",
            "POST",
            "-H",
            "Content-Type: text/plain",
            "-d",
            &hex_tx,
            &url,
        ])
        .output()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OwsLibError::BroadcastFailed(format!(
            "broadcast failed: {stderr}"
        )));
    }

    let tx_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tx_hash.is_empty() {
        return Err(OwsLibError::BroadcastFailed(
            "empty response from broadcast".into(),
        ));
    }
    Ok(tx_hash)
}

fn broadcast_cosmos(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!("{}/cosmos/tx/v1beta1/txs", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "tx_bytes": b64_tx,
        "mode": "BROADCAST_MODE_SYNC"
    });
    let resp = curl_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["tx_response"]["txhash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OwsLibError::BroadcastFailed(format!("no txhash in response: {resp}")))
}

fn broadcast_tron(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/wallet/broadcasthex", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({ "transaction": hex_tx });
    let resp = curl_post_json(&url, &body.to_string())?;
    extract_json_field(&resp, "txid")
}

fn broadcast_ton(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    use base64::Engine;
    let b64_boc = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!("{}/sendBoc", rpc_url.trim_end_matches('/'));
    let body = serde_json::json!({ "boc": b64_boc });
    let resp = curl_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)?;
    parsed["result"]["hash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OwsLibError::BroadcastFailed(format!("no hash in response: {resp}")))
}

fn curl_post_json(url: &str, body: &str) -> Result<String, OwsLibError> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            body,
            url,
        ])
        .output()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OwsLibError::BroadcastFailed(format!(
            "broadcast failed: {stderr}"
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn extract_json_field(json_str: &str, field: &str) -> Result<String, OwsLibError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)?;

    if let Some(error) = parsed.get("error") {
        return Err(OwsLibError::BroadcastFailed(format!("RPC error: {error}")));
    }

    parsed[field]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            OwsLibError::BroadcastFailed(format!("no '{field}' in response: {json_str}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers ----

    /// Build a private-key wallet directly in the vault, bypassing
    /// `import_wallet_private_key` (which touches all chains including TON).
    fn save_privkey_wallet(
        name: &str,
        privkey_hex: &str,
        passphrase: &str,
        vault: &Path,
    ) -> WalletInfo {
        let key_bytes = hex::decode(privkey_hex).unwrap();

        // Generate a random ed25519 key for the other curve
        let mut ed_key = vec![0u8; 32];
        getrandom::getrandom(&mut ed_key).unwrap();

        let keys = KeyPair {
            secp256k1: key_bytes,
            ed25519: ed_key,
        };
        let accounts = derive_all_accounts_from_keys(&keys).unwrap();
        let payload = keys.to_json_bytes();
        let crypto_envelope = encrypt(&payload, passphrase).unwrap();
        let crypto_json = serde_json::to_value(&crypto_envelope).unwrap();
        let wallet = EncryptedWallet::new(
            uuid::Uuid::new_v4().to_string(),
            name.to_string(),
            accounts,
            crypto_json,
            KeyType::PrivateKey,
        );
        vault::save_encrypted_wallet(&wallet, Some(vault)).unwrap();
        wallet_to_info(&wallet)
    }

    const TEST_PRIVKEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

    // ================================================================
    // 1. MNEMONIC GENERATION
    // ================================================================

    #[test]
    fn mnemonic_12_words() {
        let phrase = generate_mnemonic(12).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);
    }

    #[test]
    fn mnemonic_24_words() {
        let phrase = generate_mnemonic(24).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
    }

    #[test]
    fn mnemonic_invalid_word_count() {
        assert!(generate_mnemonic(15).is_err());
        assert!(generate_mnemonic(0).is_err());
        assert!(generate_mnemonic(13).is_err());
    }

    #[test]
    fn mnemonic_is_unique_each_call() {
        let a = generate_mnemonic(12).unwrap();
        let b = generate_mnemonic(12).unwrap();
        assert_ne!(a, b, "two generated mnemonics should differ");
    }

    // ================================================================
    // 2. ADDRESS DERIVATION
    // ================================================================

    #[test]
    fn derive_address_all_chains() {
        let phrase = generate_mnemonic(12).unwrap();
        let chains = ["evm", "solana", "bitcoin", "cosmos", "tron", "ton"];
        for chain in &chains {
            let addr = derive_address(&phrase, chain, None).unwrap();
            assert!(!addr.is_empty(), "address should be non-empty for {chain}");
        }
    }

    #[test]
    fn derive_address_evm_format() {
        let phrase = generate_mnemonic(12).unwrap();
        let addr = derive_address(&phrase, "evm", None).unwrap();
        assert!(addr.starts_with("0x"), "EVM address should start with 0x");
        assert_eq!(addr.len(), 42, "EVM address should be 42 chars");
    }

    #[test]
    fn derive_address_deterministic() {
        let phrase = generate_mnemonic(12).unwrap();
        let a = derive_address(&phrase, "evm", None).unwrap();
        let b = derive_address(&phrase, "evm", None).unwrap();
        assert_eq!(a, b, "same mnemonic should produce same address");
    }

    #[test]
    fn derive_address_different_index() {
        let phrase = generate_mnemonic(12).unwrap();
        let a = derive_address(&phrase, "evm", Some(0)).unwrap();
        let b = derive_address(&phrase, "evm", Some(1)).unwrap();
        assert_ne!(a, b, "different indices should produce different addresses");
    }

    #[test]
    fn derive_address_invalid_chain() {
        let phrase = generate_mnemonic(12).unwrap();
        assert!(derive_address(&phrase, "nonexistent", None).is_err());
    }

    #[test]
    fn derive_address_invalid_mnemonic() {
        assert!(derive_address("not a valid mnemonic phrase at all", "evm", None).is_err());
    }

    // ================================================================
    // 3. MNEMONIC WALLET LIFECYCLE (create → export → import → sign)
    // ================================================================

    #[test]
    fn mnemonic_wallet_create_export_reimport() {
        let v1 = tempfile::tempdir().unwrap();
        let v2 = tempfile::tempdir().unwrap();

        // Create
        let w1 = create_wallet("w1", None, None, Some(v1.path())).unwrap();
        assert!(!w1.accounts.is_empty());

        // Export mnemonic
        let phrase = export_wallet("w1", None, Some(v1.path())).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        // Re-import into fresh vault
        let w2 = import_wallet_mnemonic("w2", &phrase, None, None, Some(v2.path())).unwrap();

        // Addresses must match exactly
        assert_eq!(w1.accounts.len(), w2.accounts.len());
        for (a1, a2) in w1.accounts.iter().zip(w2.accounts.iter()) {
            assert_eq!(a1.chain_id, a2.chain_id);
            assert_eq!(
                a1.address, a2.address,
                "address mismatch for {}",
                a1.chain_id
            );
        }
    }

    #[test]
    fn mnemonic_wallet_sign_message_all_chains() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("multi-sign", None, None, Some(vault)).unwrap();

        let chains = ["evm", "solana", "bitcoin", "cosmos", "tron", "ton"];
        for chain in &chains {
            let result = sign_message(
                "multi-sign",
                chain,
                "test msg",
                None,
                None,
                None,
                Some(vault),
            );
            assert!(
                result.is_ok(),
                "sign_message should work for {chain}: {:?}",
                result.err()
            );
            let sig = result.unwrap();
            assert!(
                !sig.signature.is_empty(),
                "signature should be non-empty for {chain}"
            );
        }
    }

    #[test]
    fn mnemonic_wallet_sign_tx_all_chains() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("tx-sign", None, None, Some(vault)).unwrap();

        let generic_tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        // Solana requires a properly formatted serialized transaction:
        // [0x01 num_sigs] [64 zero bytes for sig slot] [message bytes...]
        let mut solana_tx = vec![0x01u8]; // 1 signature slot
        solana_tx.extend_from_slice(&[0u8; 64]); // placeholder signature
        solana_tx.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // message payload
        let solana_tx_hex = hex::encode(&solana_tx);

        let chains = ["evm", "solana", "bitcoin", "cosmos", "tron", "ton"];
        for chain in &chains {
            let tx = if *chain == "solana" {
                &solana_tx_hex
            } else {
                generic_tx_hex
            };
            let result = sign_transaction("tx-sign", chain, tx, None, None, Some(vault));
            assert!(
                result.is_ok(),
                "sign_transaction should work for {chain}: {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn mnemonic_wallet_signing_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("det-sign", None, None, Some(vault)).unwrap();

        let s1 = sign_message("det-sign", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("det-sign", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert_eq!(
            s1.signature, s2.signature,
            "same message should produce same signature"
        );
    }

    #[test]
    fn mnemonic_wallet_different_messages_produce_different_sigs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("diff-msg", None, None, Some(vault)).unwrap();

        let s1 = sign_message("diff-msg", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("diff-msg", "evm", "world", None, None, None, Some(vault)).unwrap();
        assert_ne!(s1.signature, s2.signature);
    }

    // ================================================================
    // 4. PRIVATE KEY WALLET LIFECYCLE
    // ================================================================

    #[test]
    fn privkey_wallet_sign_message() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-sign", TEST_PRIVKEY, "", dir.path());

        let sig = sign_message(
            "pk-sign",
            "evm",
            "hello",
            None,
            None,
            None,
            Some(dir.path()),
        )
        .unwrap();
        assert!(!sig.signature.is_empty());
        assert!(sig.recovery_id.is_some());
    }

    #[test]
    fn privkey_wallet_sign_transaction() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-tx", TEST_PRIVKEY, "", dir.path());

        let tx = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig = sign_transaction("pk-tx", "evm", tx, None, None, Some(dir.path())).unwrap();
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn privkey_wallet_export_returns_json() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-export", TEST_PRIVKEY, "", dir.path());

        let exported = export_wallet("pk-export", None, Some(dir.path())).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(
            obj["secp256k1"].as_str().unwrap(),
            TEST_PRIVKEY,
            "exported secp256k1 key should match original"
        );
        assert!(obj["ed25519"].as_str().is_some(), "should have ed25519 key");
    }

    #[test]
    fn privkey_wallet_signing_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pk-det", TEST_PRIVKEY, "", dir.path());

        let s1 = sign_message("pk-det", "evm", "test", None, None, None, Some(dir.path())).unwrap();
        let s2 = sign_message("pk-det", "evm", "test", None, None, None, Some(dir.path())).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn privkey_and_mnemonic_wallets_produce_different_sigs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("mn-w", None, None, Some(vault)).unwrap();
        save_privkey_wallet("pk-w", TEST_PRIVKEY, "", vault);

        let mn_sig = sign_message("mn-w", "evm", "hello", None, None, None, Some(vault)).unwrap();
        let pk_sig = sign_message("pk-w", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert_ne!(
            mn_sig.signature, pk_sig.signature,
            "different keys should produce different signatures"
        );
    }

    #[test]
    fn privkey_wallet_import_via_api() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = import_wallet_private_key(
            "pk-api",
            TEST_PRIVKEY,
            Some("evm"),
            None,
            Some(vault),
            None,
            None,
        )
        .unwrap();
        assert!(
            !info.accounts.is_empty(),
            "should derive at least one account"
        );

        // Should be able to sign
        let sig = sign_message("pk-api", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Export should return JSON key pair with original key
        let exported = export_wallet("pk-api", None, Some(vault)).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), TEST_PRIVKEY);
    }

    #[test]
    fn privkey_wallet_import_both_curve_keys() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let secp_key = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let ed_key = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

        let info = import_wallet_private_key(
            "pk-both",
            "",   // ignored when both curve keys provided
            None, // chain ignored too
            None,
            Some(vault),
            Some(secp_key),
            Some(ed_key),
        )
        .unwrap();

        assert_eq!(info.accounts.len(), 6, "should have all 6 chain accounts");

        // Sign on EVM (secp256k1)
        let sig = sign_message("pk-both", "evm", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Sign on Solana (ed25519)
        let sig =
            sign_message("pk-both", "solana", "hello", None, None, None, Some(vault)).unwrap();
        assert!(!sig.signature.is_empty());

        // Export should return both keys
        let exported = export_wallet("pk-both", None, Some(vault)).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), secp_key);
        assert_eq!(obj["ed25519"].as_str().unwrap(), ed_key);
    }

    // ================================================================
    // 5. PASSPHRASE PROTECTION
    // ================================================================

    #[test]
    fn passphrase_protected_mnemonic_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("pass-mn", None, Some("s3cret"), Some(vault)).unwrap();

        // Sign with correct passphrase
        let sig = sign_message(
            "pass-mn",
            "evm",
            "hello",
            Some("s3cret"),
            None,
            None,
            Some(vault),
        )
        .unwrap();
        assert!(!sig.signature.is_empty());

        // Export with correct passphrase
        let phrase = export_wallet("pass-mn", Some("s3cret"), Some(vault)).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 12);

        // Wrong passphrase should fail
        assert!(sign_message(
            "pass-mn",
            "evm",
            "hello",
            Some("wrong"),
            None,
            None,
            Some(vault)
        )
        .is_err());
        assert!(export_wallet("pass-mn", Some("wrong"), Some(vault)).is_err());

        // No passphrase should fail (defaults to empty string, which is wrong)
        assert!(sign_message("pass-mn", "evm", "hello", None, None, None, Some(vault)).is_err());
    }

    #[test]
    fn passphrase_protected_privkey_wallet() {
        let dir = tempfile::tempdir().unwrap();
        save_privkey_wallet("pass-pk", TEST_PRIVKEY, "mypass", dir.path());

        // Correct passphrase
        let sig = sign_message(
            "pass-pk",
            "evm",
            "hello",
            Some("mypass"),
            None,
            None,
            Some(dir.path()),
        )
        .unwrap();
        assert!(!sig.signature.is_empty());

        let exported = export_wallet("pass-pk", Some("mypass"), Some(dir.path())).unwrap();
        let obj: serde_json::Value = serde_json::from_str(&exported).unwrap();
        assert_eq!(obj["secp256k1"].as_str().unwrap(), TEST_PRIVKEY);

        // Wrong passphrase
        assert!(sign_message(
            "pass-pk",
            "evm",
            "hello",
            Some("wrong"),
            None,
            None,
            Some(dir.path())
        )
        .is_err());
        assert!(export_wallet("pass-pk", Some("wrong"), Some(dir.path())).is_err());
    }

    // ================================================================
    // 6. SIGNATURE VERIFICATION (prove signatures are cryptographically valid)
    // ================================================================

    #[test]
    fn evm_signature_is_recoverable() {
        use sha3::Digest;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        let info = create_wallet("verify-evm", None, None, Some(vault)).unwrap();
        let evm_addr = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .unwrap()
            .address
            .clone();

        let sig = sign_message(
            "verify-evm",
            "evm",
            "hello world",
            None,
            None,
            None,
            Some(vault),
        )
        .unwrap();

        // EVM personal_sign: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
        let msg = b"hello world";
        let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
        let mut prefixed = prefix.into_bytes();
        prefixed.extend_from_slice(msg);

        let hash = sha3::Keccak256::digest(&prefixed);
        let sig_bytes = hex::decode(&sig.signature).unwrap();
        assert_eq!(
            sig_bytes.len(),
            65,
            "EVM signature should be 65 bytes (r + s + v)"
        );

        // Recover public key from signature (v is 27 or 28 per EIP-191)
        let v = sig_bytes[64];
        assert!(
            v == 27 || v == 28,
            "EIP-191 v byte should be 27 or 28, got {v}"
        );
        let recid = k256::ecdsa::RecoveryId::try_from(v - 27).unwrap();
        let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes[..64]).unwrap();
        let recovered_key =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&hash, &ecdsa_sig, recid).unwrap();

        // Derive address from recovered key and compare
        let pubkey_bytes = recovered_key.to_encoded_point(false);
        let pubkey_hash = sha3::Keccak256::digest(&pubkey_bytes.as_bytes()[1..]);
        let recovered_addr = format!("0x{}", hex::encode(&pubkey_hash[12..]));

        // Compare case-insensitively (EIP-55 checksum)
        assert_eq!(
            recovered_addr.to_lowercase(),
            evm_addr.to_lowercase(),
            "recovered address should match wallet's EVM address"
        );
    }

    // ================================================================
    // 7. ERROR HANDLING
    // ================================================================

    #[test]
    fn error_nonexistent_wallet() {
        let dir = tempfile::tempdir().unwrap();
        assert!(get_wallet("nope", Some(dir.path())).is_err());
        assert!(export_wallet("nope", None, Some(dir.path())).is_err());
        assert!(sign_message("nope", "evm", "x", None, None, None, Some(dir.path())).is_err());
        assert!(delete_wallet("nope", Some(dir.path())).is_err());
    }

    #[test]
    fn error_duplicate_wallet_name() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("dup", None, None, Some(vault)).unwrap();
        assert!(create_wallet("dup", None, None, Some(vault)).is_err());
    }

    #[test]
    fn error_invalid_private_key_hex() {
        let dir = tempfile::tempdir().unwrap();
        assert!(import_wallet_private_key(
            "bad",
            "not-hex",
            Some("evm"),
            None,
            Some(dir.path()),
            None,
            None,
        )
        .is_err());
    }

    #[test]
    fn error_invalid_chain_for_signing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("chain-err", None, None, Some(vault)).unwrap();
        assert!(
            sign_message("chain-err", "fakecoin", "hi", None, None, None, Some(vault)).is_err()
        );
    }

    #[test]
    fn error_invalid_tx_hex() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("hex-err", None, None, Some(vault)).unwrap();
        assert!(
            sign_transaction("hex-err", "evm", "not-valid-hex!", None, None, Some(vault)).is_err()
        );
    }

    // ================================================================
    // 8. WALLET MANAGEMENT
    // ================================================================

    #[test]
    fn list_wallets_empty_vault() {
        let dir = tempfile::tempdir().unwrap();
        let wallets = list_wallets(Some(dir.path())).unwrap();
        assert!(wallets.is_empty());
    }

    #[test]
    fn get_wallet_by_name_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let info = create_wallet("lookup", None, None, Some(vault)).unwrap();

        let by_name = get_wallet("lookup", Some(vault)).unwrap();
        assert_eq!(by_name.id, info.id);

        let by_id = get_wallet(&info.id, Some(vault)).unwrap();
        assert_eq!(by_id.name, "lookup");
    }

    #[test]
    fn rename_wallet_works() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        let info = create_wallet("before", None, None, Some(vault)).unwrap();

        rename_wallet("before", "after", Some(vault)).unwrap();

        assert!(get_wallet("before", Some(vault)).is_err());
        let after = get_wallet("after", Some(vault)).unwrap();
        assert_eq!(after.id, info.id);
    }

    #[test]
    fn rename_to_existing_name_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("a", None, None, Some(vault)).unwrap();
        create_wallet("b", None, None, Some(vault)).unwrap();
        assert!(rename_wallet("a", "b", Some(vault)).is_err());
    }

    #[test]
    fn delete_wallet_removes_from_list() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("del-me", None, None, Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 1);

        delete_wallet("del-me", Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 0);
    }

    // ================================================================
    // 9. MESSAGE ENCODING
    // ================================================================

    #[test]
    fn sign_message_hex_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("hex-enc", None, None, Some(vault)).unwrap();

        // "hello" in hex
        let sig = sign_message(
            "hex-enc",
            "evm",
            "68656c6c6f",
            None,
            Some("hex"),
            None,
            Some(vault),
        )
        .unwrap();
        assert!(!sig.signature.is_empty());

        // Should match utf8 encoding of the same bytes
        let sig2 = sign_message(
            "hex-enc",
            "evm",
            "hello",
            None,
            Some("utf8"),
            None,
            Some(vault),
        )
        .unwrap();
        assert_eq!(
            sig.signature, sig2.signature,
            "hex and utf8 encoding of same bytes should produce same signature"
        );
    }

    #[test]
    fn sign_message_invalid_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        create_wallet("bad-enc", None, None, Some(vault)).unwrap();
        assert!(sign_message(
            "bad-enc",
            "evm",
            "hello",
            None,
            Some("base64"),
            None,
            Some(vault)
        )
        .is_err());
    }

    // ================================================================
    // 10. MULTI-WALLET VAULT
    // ================================================================

    #[test]
    fn multiple_wallets_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();

        create_wallet("w1", None, None, Some(vault)).unwrap();
        create_wallet("w2", None, None, Some(vault)).unwrap();
        save_privkey_wallet("w3", TEST_PRIVKEY, "", vault);

        let wallets = list_wallets(Some(vault)).unwrap();
        assert_eq!(wallets.len(), 3);

        // All can sign independently
        let s1 = sign_message("w1", "evm", "test", None, None, None, Some(vault)).unwrap();
        let s2 = sign_message("w2", "evm", "test", None, None, None, Some(vault)).unwrap();
        let s3 = sign_message("w3", "evm", "test", None, None, None, Some(vault)).unwrap();

        // All signatures should be different (different keys)
        assert_ne!(s1.signature, s2.signature);
        assert_ne!(s1.signature, s3.signature);
        assert_ne!(s2.signature, s3.signature);

        // Delete one, others survive
        delete_wallet("w2", Some(vault)).unwrap();
        assert_eq!(list_wallets(Some(vault)).unwrap().len(), 2);
        assert!(sign_message("w1", "evm", "test", None, None, None, Some(vault)).is_ok());
        assert!(sign_message("w3", "evm", "test", None, None, None, Some(vault)).is_ok());
    }

    // ================================================================
    // 11. BUG REGRESSION: CLI send_transaction broadcasts raw signature
    // ================================================================

    #[test]
    fn signed_tx_must_differ_from_raw_signature() {
        // BUG TEST: The CLI's send_transaction.rs broadcasts `output.signature`
        // (raw 65-byte sig) instead of encoding the full signed transaction via
        // signer.encode_signed_transaction(). This test proves the two are different
        // — broadcasting the raw signature sends garbage to the RPC node.
        //
        // The library's sign_and_send correctly calls encode_signed_transaction
        // before broadcast (ops.rs:481), but the CLI skips this step
        // (send_transaction.rs:43).

        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path();
        save_privkey_wallet("send-bug", TEST_PRIVKEY, "", vault);

        // Build a minimal unsigned EIP-1559 transaction
        let items: Vec<u8> = [
            ows_signer::rlp::encode_bytes(&[1]),          // chain_id = 1
            ows_signer::rlp::encode_bytes(&[]),           // nonce = 0
            ows_signer::rlp::encode_bytes(&[1]),          // maxPriorityFeePerGas
            ows_signer::rlp::encode_bytes(&[100]),        // maxFeePerGas
            ows_signer::rlp::encode_bytes(&[0x52, 0x08]), // gasLimit = 21000
            ows_signer::rlp::encode_bytes(&[0xDE, 0xAD]), // to (truncated)
            ows_signer::rlp::encode_bytes(&[]),           // value = 0
            ows_signer::rlp::encode_bytes(&[]),           // data
            ows_signer::rlp::encode_list(&[]),            // accessList
        ]
        .concat();

        let mut unsigned_tx = vec![0x02u8];
        unsigned_tx.extend_from_slice(&ows_signer::rlp::encode_list(&items));
        let tx_hex = hex::encode(&unsigned_tx);

        // Sign the transaction via the library
        let sign_result =
            sign_transaction("send-bug", "evm", &tx_hex, None, None, Some(vault)).unwrap();
        let raw_signature = hex::decode(&sign_result.signature).unwrap();

        // Now encode the full signed transaction (what the library does correctly)
        let key = decrypt_signing_key("send-bug", ChainType::Evm, "", None, Some(vault)).unwrap();
        let signer = signer_for_chain(ChainType::Evm);
        let output = signer.sign_transaction(key.expose(), &unsigned_tx).unwrap();
        let full_signed_tx = signer
            .encode_signed_transaction(&unsigned_tx, &output)
            .unwrap();

        // The raw signature (65 bytes) and the full signed tx are completely different.
        // Broadcasting the raw signature (as the CLI does) would always fail.
        assert_eq!(
            raw_signature.len(),
            65,
            "raw EVM signature should be 65 bytes (r || s || v)"
        );
        assert!(
            full_signed_tx.len() > raw_signature.len(),
            "full signed tx ({} bytes) must be larger than raw signature ({} bytes)",
            full_signed_tx.len(),
            raw_signature.len()
        );
        assert_ne!(
            raw_signature, full_signed_tx,
            "raw signature and full signed transaction must differ — \
             broadcasting the raw signature (as CLI send_transaction.rs:43 does) is wrong"
        );

        // The full signed tx should start with the EIP-1559 type byte
        assert_eq!(
            full_signed_tx[0], 0x02,
            "full signed EIP-1559 tx must start with type byte 0x02"
        );
    }
}
