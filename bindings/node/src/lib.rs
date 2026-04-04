use napi::bindgen_prelude::*;
use napi::{Env, NapiRaw};
use napi_derive::napi;
use ows_core::{Store, StoreError};
use std::path::PathBuf;

fn vault_path(p: Option<String>) -> Option<PathBuf> {
    p.map(PathBuf::from)
}

fn map_err(e: ows_lib::OwsLibError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

// ---------------------------------------------------------------------------
// JsStore — bridges a JS { get, set, remove, list? } object to Rust Store
// ---------------------------------------------------------------------------

/// Store backed by a JavaScript object with `get`, `set`, `remove`, and
/// optional `list` methods. Uses raw NAPI pointers internally because
/// `napi::Env` is not `Send + Sync`, but all calls are synchronous on the
/// main JS thread so this is safe.
struct JsStore {
    raw_env: napi::sys::napi_env,
    store_ref: napi::sys::napi_ref,
    has_list: bool,
}

// SAFETY: All Store methods are called synchronously on the main JS thread.
// The raw_env and store_ref are only accessed from that thread.
unsafe impl Send for JsStore {}
unsafe impl Sync for JsStore {}

impl Drop for JsStore {
    fn drop(&mut self) {
        unsafe {
            napi::sys::napi_delete_reference(self.raw_env, self.store_ref);
        }
    }
}

impl JsStore {
    /// Create a JsStore from a NAPI Env and a JS store object.
    fn new(env: &napi::Env, store_obj: &napi::JsObject) -> std::result::Result<Self, napi::Error> {
        let raw_env = env.raw();
        let has_list = store_obj.has_named_property("list")?;

        // Create a strong reference to prevent GC.
        let mut store_ref: napi::sys::napi_ref = std::ptr::null_mut();
        let status = unsafe {
            napi::sys::napi_create_reference(raw_env, store_obj.raw(), 1, &mut store_ref)
        };
        if status != napi::sys::Status::napi_ok {
            return Err(napi::Error::from_reason("failed to create reference to store object"));
        }

        Ok(JsStore { raw_env, store_ref, has_list })
    }

    /// Reconstruct the Env and store JsObject for a call.
    fn env_and_obj(&self) -> std::result::Result<(napi::Env, napi::JsObject), StoreError> {
        unsafe {
            let env = napi::Env::from_raw(self.raw_env);
            let mut js_value: napi::sys::napi_value = std::ptr::null_mut();
            let status = napi::sys::napi_get_reference_value(self.raw_env, self.store_ref, &mut js_value);
            if status != napi::sys::Status::napi_ok || js_value.is_null() {
                return Err(StoreError("store object has been garbage collected".to_string().into()));
            }
            let obj = napi::JsObject::from_napi_value(self.raw_env, js_value)
                .map_err(|e| StoreError(e.to_string().into()))?;
            Ok((env, obj))
        }
    }
}

fn napi_to_store_err(e: napi::Error) -> StoreError {
    StoreError(e.to_string().into())
}

impl Store for JsStore {
    fn get(&self, key: &str) -> std::result::Result<Option<String>, StoreError> {
        let (env, obj) = self.env_and_obj()?;
        let func: napi::JsFunction = obj.get_named_property("get").map_err(napi_to_store_err)?;
        let js_key = env.create_string(key).map_err(napi_to_store_err)?;
        let result: napi::JsUnknown = func.call(Some(&obj), &[js_key]).map_err(napi_to_store_err)?;
        let value_type = result.get_type().map_err(napi_to_store_err)?;
        match value_type {
            napi::ValueType::Null | napi::ValueType::Undefined => Ok(None),
            _ => {
                let js_str: napi::JsString = result.coerce_to_string().map_err(napi_to_store_err)?;
                let utf8 = js_str.into_utf8().map_err(napi_to_store_err)?;
                let s = utf8.as_str().map_err(|e| StoreError(e.to_string().into()))?.to_string();
                Ok(Some(s))
            }
        }
    }

    fn set(&self, key: &str, value: &str) -> std::result::Result<(), StoreError> {
        let (env, obj) = self.env_and_obj()?;
        let func: napi::JsFunction = obj.get_named_property("set").map_err(napi_to_store_err)?;
        let js_key = env.create_string(key).map_err(napi_to_store_err)?;
        let js_value = env.create_string(value).map_err(napi_to_store_err)?;
        func.call(Some(&obj), &[js_key, js_value]).map_err(napi_to_store_err)?;
        Ok(())
    }

    fn remove(&self, key: &str) -> std::result::Result<(), StoreError> {
        let (env, obj) = self.env_and_obj()?;
        let func: napi::JsFunction = obj.get_named_property("remove").map_err(napi_to_store_err)?;
        let js_key = env.create_string(key).map_err(napi_to_store_err)?;
        func.call(Some(&obj), &[js_key]).map_err(napi_to_store_err)?;
        Ok(())
    }

    fn list(&self, prefix: &str) -> std::result::Result<Vec<String>, StoreError> {
        if !self.has_list {
            // Default index-based list.
            let index_key = format!("_index/{prefix}");
            return match self.get(&index_key)? {
                Some(json) => Ok(serde_json::from_str(&json)?),
                None => Ok(vec![]),
            };
        }

        let (env, obj) = self.env_and_obj()?;
        let func: napi::JsFunction = obj.get_named_property("list").map_err(napi_to_store_err)?;
        let js_prefix = env.create_string(prefix).map_err(napi_to_store_err)?;
        let result: napi::JsObject = func
            .call(Some(&obj), &[js_prefix])
            .map_err(napi_to_store_err)?
            .coerce_to_object()
            .map_err(napi_to_store_err)?;

        let length: u32 = result
            .get_named_property::<napi::JsNumber>("length")
            .map_err(napi_to_store_err)?
            .get_uint32()
            .map_err(napi_to_store_err)?;

        let mut keys = Vec::with_capacity(length as usize);
        for i in 0..length {
            let item: napi::JsString = result.get_element::<napi::JsString>(i).map_err(napi_to_store_err)?;
            let utf8 = item.into_utf8().map_err(napi_to_store_err)?;
            let s = utf8.as_str().map_err(|e| StoreError(e.to_string().into()))?.to_string();
            keys.push(s);
        }

        Ok(keys)
    }
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
pub fn derive_address(mnemonic: String, chain: String, index: Option<u32>) -> Result<String> {
    ows_lib::derive_address(&mnemonic, &chain, index).map_err(map_err)
}

/// Create a new universal wallet (derives addresses for all chains).
#[napi]
pub fn create_wallet(
    name: String,
    passphrase: Option<String>,
    words: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::create_wallet(
        &name,
        words,
        passphrase.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// Import a wallet from a mnemonic phrase (derives addresses for all chains).
#[napi]
pub fn import_wallet_mnemonic(
    name: String,
    mnemonic: String,
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_mnemonic(
        &name,
        &mnemonic,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(WalletInfo::from)
    .map_err(map_err)
}

/// Import a wallet from a hex-encoded private key.
/// All 6 chains are supported: the provided key is used for its curve's chains,
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
    passphrase: Option<String>,
    vault_path_opt: Option<String>,
    chain: Option<String>,
    secp256k1_key: Option<String>,
    ed25519_key: Option<String>,
) -> Result<WalletInfo> {
    ows_lib::import_wallet_private_key(
        &name,
        &private_key_hex,
        chain.as_deref(),
        passphrase.as_deref(),
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
    passphrase: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<String> {
    ows_lib::export_wallet(
        &name_or_id,
        passphrase.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)
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
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_transaction(
        &wallet,
        &chain,
        &tx_hex,
        passphrase.as_deref(),
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
    passphrase: Option<String>,
    encoding: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_message(
        &wallet,
        &chain,
        &message,
        passphrase.as_deref(),
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
    passphrase: Option<String>,
    index: Option<u32>,
    vault_path_opt: Option<String>,
) -> Result<SignResult> {
    ows_lib::sign_typed_data(
        &wallet,
        &chain,
        &typed_data_json,
        passphrase.as_deref(),
        index,
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SignResult {
        signature: r.signature,
        recovery_id: r.recovery_id.map(|v| v as u32),
    })
    .map_err(map_err)
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

/// Register a policy from a JSON string.
#[napi]
pub fn create_policy(policy_json: String, vault_path_opt: Option<String>) -> Result<()> {
    let policy: ows_core::Policy =
        serde_json::from_str(&policy_json).map_err(|e| napi::Error::from_reason(e.to_string()))?;
    ows_lib::policy_store::save_policy(&policy, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

/// List all registered policies.
#[napi]
pub fn list_policies(vault_path_opt: Option<String>) -> Result<Vec<serde_json::Value>> {
    let policies =
        ows_lib::policy_store::list_policies(vault_path(vault_path_opt).as_deref())
            .map_err(map_err)?;
    policies
        .iter()
        .map(|p| serde_json::to_value(p).map_err(|e| napi::Error::from_reason(e.to_string())))
        .collect()
}

/// Get a single policy by ID.
#[napi]
pub fn get_policy(id: String, vault_path_opt: Option<String>) -> Result<serde_json::Value> {
    let policy =
        ows_lib::policy_store::load_policy(&id, vault_path(vault_path_opt).as_deref())
            .map_err(map_err)?;
    serde_json::to_value(&policy).map_err(|e| napi::Error::from_reason(e.to_string()))
}

/// Delete a policy by ID.
#[napi]
pub fn delete_policy(id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::policy_store::delete_policy(&id, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

// ---------------------------------------------------------------------------
// API key management
// ---------------------------------------------------------------------------

/// API key creation result.
#[napi(object)]
pub struct ApiKeyResult {
    /// The raw token (shown once — caller must save it).
    pub token: String,
    /// The key file ID.
    pub id: String,
    pub name: String,
}

/// Create an API key for agent access to wallets.
/// Returns the raw token (shown once) and key metadata.
#[napi]
pub fn create_api_key(
    name: String,
    wallet_ids: Vec<String>,
    policy_ids: Vec<String>,
    passphrase: String,
    expires_at: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<ApiKeyResult> {
    let (token, key_file) = ows_lib::key_ops::create_api_key(
        &name,
        &wallet_ids,
        &policy_ids,
        &passphrase,
        expires_at.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map_err(map_err)?;

    Ok(ApiKeyResult {
        token,
        id: key_file.id,
        name: key_file.name,
    })
}

/// List all API keys (tokens are never returned).
#[napi]
pub fn list_api_keys(vault_path_opt: Option<String>) -> Result<Vec<serde_json::Value>> {
    let keys =
        ows_lib::key_store::list_api_keys(vault_path(vault_path_opt).as_deref())
            .map_err(map_err)?;
    keys.iter()
        .map(|k| {
            // Strip wallet_secrets from the output — never expose encrypted material
            let mut v = serde_json::to_value(k)
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;
            v.as_object_mut().map(|m| m.remove("wallet_secrets"));
            Ok(v)
        })
        .collect()
}

/// Revoke (delete) an API key by ID.
#[napi]
pub fn revoke_api_key(id: String, vault_path_opt: Option<String>) -> Result<()> {
    ows_lib::key_store::delete_api_key(&id, vault_path(vault_path_opt).as_deref())
        .map_err(map_err)
}

/// Sign and broadcast a transaction. Returns the transaction hash.
#[napi]
pub fn sign_and_send(
    wallet: String,
    chain: String,
    tx_hex: String,
    passphrase: Option<String>,
    index: Option<u32>,
    rpc_url: Option<String>,
    vault_path_opt: Option<String>,
) -> Result<SendResult> {
    ows_lib::sign_and_send(
        &wallet,
        &chain,
        &tx_hex,
        passphrase.as_deref(),
        index,
        rpc_url.as_deref(),
        vault_path(vault_path_opt).as_deref(),
    )
    .map(|r| SendResult { tx_hash: r.tx_hash })
    .map_err(map_err)
}

// ---------------------------------------------------------------------------
// OWS class — pluggable store support
// ---------------------------------------------------------------------------

/// OWS client with a pluggable store backend.
///
/// ```js
/// // Default filesystem store (~/.ows)
/// const ows = new OWS();
///
/// // Custom vault path
/// const ows = new OWS({ vaultPath: "/custom/path" });
///
/// // Custom store
/// const ows = new OWS({
///   store: {
///     get: (key) => myDb.get(key),
///     set: (key, value) => myDb.set(key, value),
///     remove: (key) => myDb.delete(key),
///     list: (prefix) => myDb.keysWithPrefix(prefix),  // optional
///   }
/// });
/// ```
/// Create an OWS instance with an optional custom store.
///
/// ```js
/// // Default filesystem store
/// const ows = createOWS();
///
/// // Custom store
/// const ows = createOWS({
///   store: {
///     get: (key) => myDb.get(key),
///     set: (key, value) => myDb.set(key, value),
///     remove: (key) => myDb.delete(key),
///     list: (prefix) => myDb.keysWithPrefix(prefix),  // optional
///   }
/// });
/// ```
/// Create an OWS instance. Called as `createOws()` or `createOws({ store: ... })`.
///
/// The store object must implement: `get(key: string): string | null`,
/// `set(key: string, value: string): void`, `remove(key: string): void`,
/// and optionally `list(prefix: string): string[]`.
#[napi(
    ts_args_type = "options?: { store?: { get: (key: string) => string | null, set: (key: string, value: string) => void, remove: (key: string) => void, list?: (prefix: string) => string[] }, vaultPath?: string }"
)]
pub fn create_ows(env: Env, options: Option<napi::JsObject>) -> Result<OWS> {
    let store: Box<dyn Store> = match options {
        Some(opts) => {
            let has_store = opts.has_named_property("store")
                .map_err(|e| napi::Error::from_reason(e.to_string()))?;

            if has_store {
                let store_obj: napi::JsObject = opts.get_named_property("store")
                    .map_err(|e| napi::Error::from_reason(e.to_string()))?;
                Box::new(JsStore::new(&env, &store_obj)?)
            } else {
                let vault_path: Option<String> = opts.get_named_property::<napi::JsUnknown>("vaultPath")
                    .ok()
                    .and_then(|v| v.coerce_to_string().ok())
                    .and_then(|s| s.into_utf8().ok())
                    .and_then(|u| u.as_str().ok().map(|s| s.to_string()));
                Box::new(ows_lib::FsStore::new(
                    vault_path.as_deref().map(std::path::Path::new),
                ))
            }
        }
        None => Box::new(ows_lib::FsStore::new(None)),
    };
    Ok(OWS { store })
}

#[napi]
pub struct OWS {
    store: Box<dyn Store>,
}

#[napi]
impl OWS {

    #[napi]
    pub fn create_wallet(
        &self,
        name: String,
        passphrase: Option<String>,
        words: Option<u32>,
    ) -> Result<WalletInfo> {
        ows_lib::create_wallet_with_store(
            &name,
            words,
            passphrase.as_deref(),
            &*self.store,
        )
        .map(WalletInfo::from)
        .map_err(map_err)
    }

    #[napi]
    pub fn import_wallet_mnemonic(
        &self,
        name: String,
        mnemonic: String,
        passphrase: Option<String>,
        index: Option<u32>,
    ) -> Result<WalletInfo> {
        ows_lib::import_wallet_mnemonic_with_store(
            &name,
            &mnemonic,
            passphrase.as_deref(),
            index,
            &*self.store,
        )
        .map(WalletInfo::from)
        .map_err(map_err)
    }

    #[napi]
    pub fn import_wallet_private_key(
        &self,
        name: String,
        private_key_hex: String,
        passphrase: Option<String>,
        chain: Option<String>,
        secp256k1_key: Option<String>,
        ed25519_key: Option<String>,
    ) -> Result<WalletInfo> {
        ows_lib::import_wallet_private_key_with_store(
            &name,
            &private_key_hex,
            chain.as_deref(),
            passphrase.as_deref(),
            &*self.store,
            secp256k1_key.as_deref(),
            ed25519_key.as_deref(),
        )
        .map(WalletInfo::from)
        .map_err(map_err)
    }

    #[napi]
    pub fn list_wallets(&self) -> Result<Vec<WalletInfo>> {
        ows_lib::list_wallets_with_store(&*self.store)
            .map(|ws| ws.into_iter().map(WalletInfo::from).collect())
            .map_err(map_err)
    }

    #[napi]
    pub fn get_wallet(&self, name_or_id: String) -> Result<WalletInfo> {
        ows_lib::get_wallet_with_store(&name_or_id, &*self.store)
            .map(WalletInfo::from)
            .map_err(map_err)
    }

    #[napi]
    pub fn delete_wallet(&self, name_or_id: String) -> Result<()> {
        ows_lib::delete_wallet_with_store(&name_or_id, &*self.store).map_err(map_err)
    }

    #[napi]
    pub fn export_wallet(
        &self,
        name_or_id: String,
        passphrase: Option<String>,
    ) -> Result<String> {
        ows_lib::export_wallet_with_store(
            &name_or_id,
            passphrase.as_deref(),
            &*self.store,
        )
        .map_err(map_err)
    }

    #[napi]
    pub fn rename_wallet(&self, name_or_id: String, new_name: String) -> Result<()> {
        ows_lib::rename_wallet_with_store(&name_or_id, &new_name, &*self.store)
            .map_err(map_err)
    }

    #[napi]
    pub fn sign_transaction(
        &self,
        wallet: String,
        chain: String,
        tx_hex: String,
        passphrase: Option<String>,
        index: Option<u32>,
    ) -> Result<SignResult> {
        ows_lib::sign_transaction_with_store(
            &wallet,
            &chain,
            &tx_hex,
            passphrase.as_deref(),
            index,
            &*self.store,
        )
        .map(|r| SignResult {
            signature: r.signature,
            recovery_id: r.recovery_id.map(|v| v as u32),
        })
        .map_err(map_err)
    }

    #[napi]
    pub fn sign_message(
        &self,
        wallet: String,
        chain: String,
        message: String,
        passphrase: Option<String>,
        encoding: Option<String>,
        index: Option<u32>,
    ) -> Result<SignResult> {
        ows_lib::sign_message_with_store(
            &wallet,
            &chain,
            &message,
            passphrase.as_deref(),
            encoding.as_deref(),
            index,
            &*self.store,
        )
        .map(|r| SignResult {
            signature: r.signature,
            recovery_id: r.recovery_id.map(|v| v as u32),
        })
        .map_err(map_err)
    }

    #[napi]
    pub fn sign_typed_data(
        &self,
        wallet: String,
        chain: String,
        typed_data_json: String,
        passphrase: Option<String>,
        index: Option<u32>,
    ) -> Result<SignResult> {
        ows_lib::sign_typed_data_with_store(
            &wallet,
            &chain,
            &typed_data_json,
            passphrase.as_deref(),
            index,
            &*self.store,
        )
        .map(|r| SignResult {
            signature: r.signature,
            recovery_id: r.recovery_id.map(|v| v as u32),
        })
        .map_err(map_err)
    }

    #[napi]
    pub fn create_policy(&self, policy_json: String) -> Result<()> {
        let policy: ows_core::Policy = serde_json::from_str(&policy_json)
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        ows_lib::policy_store::save_policy_with_store(&policy, &*self.store).map_err(map_err)
    }

    #[napi]
    pub fn list_policies(&self) -> Result<Vec<serde_json::Value>> {
        let policies =
            ows_lib::policy_store::list_policies_with_store(&*self.store).map_err(map_err)?;
        policies
            .iter()
            .map(|p| serde_json::to_value(p).map_err(|e| napi::Error::from_reason(e.to_string())))
            .collect()
    }

    #[napi]
    pub fn get_policy(&self, id: String) -> Result<serde_json::Value> {
        let policy =
            ows_lib::policy_store::load_policy_with_store(&id, &*self.store).map_err(map_err)?;
        serde_json::to_value(&policy).map_err(|e| napi::Error::from_reason(e.to_string()))
    }

    #[napi]
    pub fn delete_policy(&self, id: String) -> Result<()> {
        ows_lib::policy_store::delete_policy_with_store(&id, &*self.store).map_err(map_err)
    }

    #[napi]
    pub fn create_api_key(
        &self,
        name: String,
        wallet_ids: Vec<String>,
        policy_ids: Vec<String>,
        passphrase: String,
        expires_at: Option<String>,
    ) -> Result<ApiKeyResult> {
        let (token, key_file) = ows_lib::key_ops::create_api_key_with_store(
            &name,
            &wallet_ids,
            &policy_ids,
            &passphrase,
            expires_at.as_deref(),
            &*self.store,
        )
        .map_err(map_err)?;

        Ok(ApiKeyResult {
            token,
            id: key_file.id,
            name: key_file.name,
        })
    }

    #[napi]
    pub fn list_api_keys(&self) -> Result<Vec<serde_json::Value>> {
        let keys =
            ows_lib::key_store::list_api_keys_with_store(&*self.store).map_err(map_err)?;
        keys.iter()
            .map(|k| {
                let mut v = serde_json::to_value(k)
                    .map_err(|e| napi::Error::from_reason(e.to_string()))?;
                v.as_object_mut().map(|m| m.remove("wallet_secrets"));
                Ok(v)
            })
            .collect()
    }

    #[napi]
    pub fn revoke_api_key(&self, id: String) -> Result<()> {
        ows_lib::key_store::delete_api_key_with_store(&id, &*self.store).map_err(map_err)
    }
}
