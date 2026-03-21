use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::path::PathBuf;

fn vault_path(p: Option<String>) -> Option<PathBuf> {
    p.map(PathBuf::from)
}

fn map_err(e: ows_lib::OwsLibError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// A single account within a wallet (one per chain family).
#[napi(object)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Wallet information returned by create/import/list/get operations.
#[napi(object)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

impl From<ows_lib::WalletInfo> for WalletInfo {
    fn from(w: ows_lib::WalletInfo) -> Self {
        WalletInfo {
            id: w.id,
            name: w.name,
            accounts: w
                .accounts
                .into_iter()
                .map(|a| AccountInfo {
                    chain_id: a.chain_id,
                    address: a.address,
                    derivation_path: a.derivation_path,
                })
                .collect(),
            created_at: w.created_at,
        }
    }
}

/// Result from a signing operation.
#[napi(object)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u32>,
}

/// Result from a sign-and-send operation.
#[napi(object)]
pub struct SendResult {
    pub tx_hash: String,
}

/// Generate a new BIP-39 mnemonic phrase.
#[napi]
pub fn generate_mnemonic(words: Option<u32>) -> Result<String> {
    ows_lib::generate_mnemonic(words.unwrap_or(12)).map_err(map_err)
}

/// Derive an address from a mnemonic for the given chain.
#[napi]
pub fn derive_address(
    mnemonic: String,
    chain: String,
    index: Option<u32>,
) -> Result<String> {
    ows_lib::derive_address(&mnemonic, &chain, index).map_err(map_err)
}

/// Create a new universal wallet (derives addresses for all chains).
#[napi]
pub fn create_wallet(
    name: String,
    words: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::create_wallet(&name, words, vault_path(vault_path_opt).as_deref())
        .map(WalletInfo::from)
        .map_err(map_err)
}

/// Import a wallet from a mnemonic phrase (derives addresses for all chains).
#[napi]
pub fn import_wallet_mnemonic(
    name: String,
    mnemonic: String,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_mnemonic(&name, &mnemonic, index, vault_path(vault_path_opt).as_deref())
        .map(WalletInfo::from)
        .map_err(map_err)
}

/// Import a wallet from a hex-encoded private key.
/// All 7 chain families are supported: the provided key is used for its curve's chains,
/// and a random key is generated for the other curve.
/// The optional `chain` parameter specifies the key's source chain (e.g. "evm", "solana")
/// to determine which curve it uses. Defaults to "evm" (secp256k1).
///
/// Alternatively, provide explicit keys for each curve via `secp256k1Key` and `ed25519Key`.
/// When both are given, `privateKeyHex` and `chain` are ignored.
#[napi]
pub fn import_wallet_private_key(
    name: String,
    private_key_hex: String,
    chain: Option<String>,
    vault_path_opt: Option<String>,
    secp256k1_key: Option<String>,
    ed25519_key: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_private_key(
        &name,
        &private_key_hex,
        chain.as_deref(),
        vault_path(vault_path_opt).as_deref(),
        secp256k1_key.as_deref(),
        ed25519_key.as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// List all wallets in the vault.
#[napi]
pub fn list_wallets(vault_path_opt: Option<String>) -> Result<Vec<WalletInfo>> {
    ows_lib::list_wallets(vault_path(vault_path_opt).as_deref())
        .map(|ws| ws.into_iter().map(WalletInfo::from).collect())
        .map_err(map_err)
}

/// Get a single wallet by name or ID.
#[napi]
pub fn get_wallet(name_or_id: String, vault_path_opt: Option<String>) -> Result<WalletInfo> {
    ows_lib::get_wallet(&name_or_id, vault_path(vault_path_opt).as_deref())
        .map(WalletInfo::from)
        .map_err(map_err)
}

/// Delete a wallet from the vault.
#[napi]
pub fn delete_wallet(name_or_id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::delete_wallet(&name_or_id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

/// Export a wallet's secret (mnemonic or private key).
#[napi]
pub fn export_wallet(
    name_or_id: String,
    vault_path_opt: Option<String>,
) -> Result<String> {
    ows_lib::export_wallet(&name_or_id, vault_path(vault_path_opt).as_deref()).map_err(map_err)
}

/// Rename a wallet.
#[napi]
pub fn rename_wallet(
    name_or_id: String,
    new_name: String,
    vault_path_opt: Option<String>,
) -> Result<()> {
    ows_lib::rename_wallet(
        &name_or_id,
        &new_name,
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
}

/// Sign a transaction. Returns hex-encoded signature.
#[napi]
pub fn sign_transaction(
    wallet: String,
    chain: String,
    tx_hex: String,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_transaction(
        &wallet,
        &chain,
        &tx_hex,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign a message. Returns hex-encoded signature.
#[napi]
pub fn sign_message(
    wallet: String,
    chain: String,
    message: String,
    encoding: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_message(
        &wallet,
        &chain,
        &message,
        encoding.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign EIP-712 typed structured data (EVM only). Returns hex-encoded signature.
#[napi]
pub fn sign_typed_data(
    wallet: String,
    chain: String,
    typed_data_json: String,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_typed_data(
        &wallet,
        &chain,
        &typed_data_json,
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

/// Sign and broadcast a transaction. Returns the transaction hash.
#[napi]
pub fn sign_and_send(
    wallet: String,
    chain: String,
    tx_hex: String,
    index: Option<u32>,
    rpc_url: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<SendResult> {
    ows_lib::sign_and_send(
        &wallet,
        &chain,
        &tx_hex,
        index,
        rpc_url.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SendResult {
        tx_hash: r.tx_hash,
    })
    .map_err(map_err)
}
