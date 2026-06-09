#![allow(clippy::too_many_arguments)]

use chrono::DateTime;
use ows_core::{
    default_chain_for_type, parse_chain as parse_ows_chain, ApiKeyFile, Chain, ChainType,
    EncryptedWallet, KeyType, Policy, PolicyResult, PolicyRule, WalletAccount, ALL_CHAIN_TYPES,
};
use ows_signer::{
    decrypt, eip712, encrypt, encrypt_with_hkdf, signer_for_chain, CryptoEnvelope, CryptoError,
    Curve, HdDeriver, Mnemonic, MnemonicStrength, SecretBytes, SignerError,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

const TOKEN_PREFIX: &str = "ows_key_";

type WebResult<T> = Result<T, WebError>;

#[derive(Debug)]
struct WebError {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorPayload<'a> {
    code: &'a str,
    message: &'a str,
}

impl WebError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<serde_json::Error> for WebError {
    fn from(value: serde_json::Error) -> Self {
        WebError::new("INVALID_INPUT", format!("JSON error: {value}"))
    }
}

impl From<ows_signer::hd::HdError> for WebError {
    fn from(value: ows_signer::hd::HdError) -> Self {
        WebError::new("INVALID_INPUT", value.to_string())
    }
}

impl From<ows_signer::mnemonic::MnemonicError> for WebError {
    fn from(value: ows_signer::mnemonic::MnemonicError) -> Self {
        WebError::new("INVALID_INPUT", value.to_string())
    }
}

impl From<SignerError> for WebError {
    fn from(value: SignerError) -> Self {
        WebError::new("INVALID_INPUT", value.to_string())
    }
}

fn crypto_error(value: CryptoError) -> WebError {
    match value {
        CryptoError::DecryptionFailed(_) => {
            WebError::new("INVALID_PASSPHRASE", "invalid passphrase")
        }
        _ => WebError::new("INVALID_INPUT", value.to_string()),
    }
}

fn invalid_input(message: impl Into<String>) -> WebError {
    WebError::new("INVALID_INPUT", message)
}

fn to_js_error(error: WebError) -> JsValue {
    let payload = ErrorPayload {
        code: error.code,
        message: &error.message,
    };
    JsValue::from_str(&serde_json::to_string(&payload).unwrap_or_else(|_| error.to_string()))
}

fn json_result<T: Serialize>(result: WebResult<T>) -> Result<String, JsValue> {
    result
        .and_then(|value| serde_json::to_string(&value).map_err(WebError::from))
        .map_err(to_js_error)
}

fn string_result(result: WebResult<String>) -> Result<String, JsValue> {
    result.map_err(to_js_error)
}

fn parse_json<T: DeserializeOwned>(input: &str, label: &str) -> WebResult<T> {
    serde_json::from_str(input).map_err(|e| invalid_input(format!("failed to parse {label}: {e}")))
}

fn parse_wallets(input: &str) -> WebResult<Vec<EncryptedWallet>> {
    parse_json(input, "wallets")
}

fn parse_keys(input: &str) -> WebResult<Vec<ApiKeyFile>> {
    parse_json(input, "API keys")
}

fn parse_policies(input: &str) -> WebResult<Vec<Policy>> {
    parse_json(input, "policies")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletInfo {
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    pub recovery_id: Option<u8>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletWriteResult {
    info: WalletInfo,
    wallet: EncryptedWallet,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteResult {
    id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyResult {
    id: String,
    key: ApiKeyFile,
    name: String,
    token: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicApiKey {
    created_at: String,
    expires_at: Option<String>,
    id: String,
    name: String,
    policy_ids: Vec<String>,
    token_hash: String,
    wallet_ids: Vec<String>,
}

fn wallet_to_info(wallet: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        accounts: wallet
            .accounts
            .iter()
            .map(|account| AccountInfo {
                chain_id: account.chain_id.clone(),
                address: account.address.clone(),
                derivation_path: account.derivation_path.clone(),
            })
            .collect(),
        created_at: wallet.created_at.clone(),
        id: wallet.id.clone(),
        name: wallet.name.clone(),
    }
}

fn public_api_key(key: &ApiKeyFile) -> PublicApiKey {
    PublicApiKey {
        created_at: key.created_at.clone(),
        expires_at: key.expires_at.clone(),
        id: key.id.clone(),
        name: key.name.clone(),
        policy_ids: key.policy_ids.clone(),
        token_hash: key.token_hash.clone(),
        wallet_ids: key.wallet_ids.clone(),
    }
}

fn encrypted_wallet(
    id: String,
    name: String,
    accounts: Vec<WalletAccount>,
    crypto: serde_json::Value,
    key_type: KeyType,
    created_at: String,
) -> EncryptedWallet {
    EncryptedWallet {
        ows_version: 2,
        id,
        name,
        created_at,
        chain_type: None,
        accounts,
        crypto,
        key_type,
        metadata: serde_json::Value::Null,
    }
}

fn parse_chain(input: &str) -> WebResult<Chain> {
    parse_ows_chain(input).map_err(|message| WebError::new("CAIP_PARSE_ERROR", message))
}

fn find_wallet_index(wallets: &[EncryptedWallet], name_or_id: &str) -> WebResult<usize> {
    if let Some(index) = wallets.iter().position(|wallet| wallet.id == name_or_id) {
        return Ok(index);
    }

    let matches: Vec<usize> = wallets
        .iter()
        .enumerate()
        .filter_map(|(index, wallet)| (wallet.name == name_or_id).then_some(index))
        .collect();

    match matches.len() {
        0 => Err(WebError::new(
            "WALLET_NOT_FOUND",
            format!("wallet not found: '{name_or_id}'"),
        )),
        1 => Ok(matches[0]),
        count => Err(invalid_input(format!(
            "ambiguous wallet name '{name_or_id}' matches {count} wallets; use the wallet ID instead"
        ))),
    }
}

fn find_wallet<'a>(
    wallets: &'a [EncryptedWallet],
    name_or_id: &str,
) -> WebResult<&'a EncryptedWallet> {
    let index = find_wallet_index(wallets, name_or_id)?;
    Ok(&wallets[index])
}

fn ensure_wallet_name_available(wallets: &[EncryptedWallet], name: &str) -> WebResult<()> {
    if wallets.iter().any(|wallet| wallet.name == name) {
        return Err(WebError::new(
            "WALLET_NAME_EXISTS",
            format!("wallet name already exists: '{name}'"),
        ));
    }
    Ok(())
}

fn derive_all_accounts(mnemonic: &Mnemonic, index: u32) -> WebResult<Vec<WalletAccount>> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for chain_type in ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(chain_type);
        let signer = signer_for_chain(chain_type);
        let path = signer.default_derivation_path(index);
        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, signer.curve())?;
        let address = signer.derive_address(key.expose())?;
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

struct KeyPair {
    ed25519: Vec<u8>,
    secp256k1: Vec<u8>,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.ed25519.zeroize();
        self.secp256k1.zeroize();
    }
}

impl KeyPair {
    fn key_for_curve(&self, curve: Curve) -> &[u8] {
        match curve {
            Curve::Ed25519 => &self.ed25519,
            Curve::Secp256k1 => &self.secp256k1,
        }
    }

    fn to_json_bytes(&self) -> Vec<u8> {
        serde_json::json!({
            "ed25519": hex::encode(&self.ed25519),
            "secp256k1": hex::encode(&self.secp256k1),
        })
        .to_string()
        .into_bytes()
    }

    fn from_json_bytes(bytes: &[u8]) -> WebResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        let ed25519 = value["ed25519"]
            .as_str()
            .ok_or_else(|| invalid_input("missing ed25519 key"))?;
        let secp256k1 = value["secp256k1"]
            .as_str()
            .ok_or_else(|| invalid_input("missing secp256k1 key"))?;
        Ok(KeyPair {
            ed25519: decode_hex_key(ed25519)?,
            secp256k1: decode_hex_key(secp256k1)?,
        })
    }
}

fn derive_all_accounts_from_keys(keys: &KeyPair) -> WebResult<Vec<WalletAccount>> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for chain_type in ALL_CHAIN_TYPES {
        let signer = signer_for_chain(chain_type);
        let key = keys.key_for_curve(signer.curve());
        let address = signer.derive_address(key)?;
        let chain = default_chain_for_type(chain_type);
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: String::new(),
        });
    }
    Ok(accounts)
}

fn decode_hex_key(input: &str) -> WebResult<Vec<u8>> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    hex::decode(trimmed).map_err(|e| invalid_input(format!("invalid hex private key: {e}")))
}

fn secret_to_signing_key(
    secret: &SecretBytes,
    key_type: &KeyType,
    chain_type: ChainType,
    index: u32,
) -> WebResult<SecretBytes> {
    match key_type {
        KeyType::Mnemonic => {
            let phrase = std::str::from_utf8(secret.expose())
                .map_err(|_| invalid_input("wallet contains invalid UTF-8 mnemonic"))?;
            let mnemonic = Mnemonic::from_phrase(phrase)?;
            let signer = signer_for_chain(chain_type);
            let path = signer.default_derivation_path(index);
            Ok(HdDeriver::derive_from_mnemonic(
                &mnemonic,
                "",
                &path,
                signer.curve(),
            )?)
        }
        KeyType::PrivateKey => {
            let keys = KeyPair::from_json_bytes(secret.expose())?;
            let signer = signer_for_chain(chain_type);
            Ok(SecretBytes::from_slice(keys.key_for_curve(signer.curve())))
        }
    }
}

fn decrypt_signing_key(
    wallet: &EncryptedWallet,
    chain_type: ChainType,
    passphrase: &str,
    index: u32,
) -> WebResult<SecretBytes> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
    let secret = decrypt(&envelope, passphrase).map_err(crypto_error)?;
    secret_to_signing_key(&secret, &wallet.key_type, chain_type, index)
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn find_api_key_by_token<'a>(keys: &'a [ApiKeyFile], token: &str) -> WebResult<&'a ApiKeyFile> {
    let token_hash = hash_token(token);
    keys.iter()
        .find(|key| key.token_hash == token_hash)
        .ok_or(WebError::new("API_KEY_NOT_FOUND", "API key not found"))
}

fn find_policy<'a>(policies: &'a [Policy], id: &str) -> WebResult<&'a Policy> {
    policies
        .iter()
        .find(|policy| policy.id == id)
        .ok_or_else(|| invalid_input(format!("policy not found: {id}")))
}

fn reject_executable_policy(policy: &Policy) -> WebResult<()> {
    if policy.executable.is_some() {
        return Err(WebError::new(
            "UNSUPPORTED_BROWSER_FEATURE",
            "executable policies are not supported in browser",
        ));
    }
    Ok(())
}

fn parse_timestamp(input: &str, label: &str) -> WebResult<DateTime<chrono::FixedOffset>> {
    DateTime::parse_from_rfc3339(input)
        .map_err(|e| invalid_input(format!("invalid {label} timestamp '{input}': {e}")))
}

fn check_expiry(key: &ApiKeyFile, now_iso: &str) -> WebResult<()> {
    if let Some(expires_at) = &key.expires_at {
        let now = parse_timestamp(now_iso, "current")?;
        let expires = parse_timestamp(expires_at, "expires_at")?;
        if now > expires {
            return Err(WebError::new(
                "API_KEY_EXPIRED",
                format!("API key expired: {}", key.id),
            ));
        }
    }
    Ok(())
}

fn date_from_timestamp(now_iso: &str) -> String {
    now_iso.split('T').next().unwrap_or(now_iso).to_string()
}

fn parse_domain_chain_id(value: &serde_json::Value) -> Option<u64> {
    value
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| value.as_u64())
}

fn evaluate_policies(policies: &[Policy], context: &ows_core::PolicyContext) -> PolicyResult {
    for policy in policies {
        if let Err(error) = reject_executable_policy(policy) {
            return PolicyResult::denied(&policy.id, error.message);
        }

        for rule in &policy.rules {
            let result = match rule {
                PolicyRule::AllowedChains { chain_ids } => {
                    if chain_ids
                        .iter()
                        .any(|chain_id| chain_id == &context.chain_id)
                    {
                        PolicyResult::allowed()
                    } else {
                        PolicyResult::denied(
                            &policy.id,
                            format!("chain {} not in allowlist", context.chain_id),
                        )
                    }
                }
                PolicyRule::AllowedTypedDataContracts { contracts } => match &context.typed_data {
                    None => PolicyResult::allowed(),
                    Some(typed_data) => match &typed_data.verifying_contract {
                        None => PolicyResult::denied(
                            &policy.id,
                            "typed data has no verifyingContract but policy requires one",
                        ),
                        Some(contract) => {
                            let contract_lower = contract.to_lowercase();
                            if contracts
                                .iter()
                                .any(|candidate| candidate.to_lowercase() == contract_lower)
                            {
                                PolicyResult::allowed()
                            } else {
                                PolicyResult::denied(
                                    &policy.id,
                                    format!("verifyingContract {contract} not in allowed list"),
                                )
                            }
                        }
                    },
                },
                PolicyRule::ExpiresAt { timestamp } => {
                    match (
                        parse_timestamp(&context.timestamp, "current"),
                        parse_timestamp(timestamp, "policy expiry"),
                    ) {
                        (Ok(now), Ok(expires)) if now > expires => PolicyResult::denied(
                            &policy.id,
                            format!("policy expired at {timestamp}"),
                        ),
                        (Ok(_), Ok(_)) => PolicyResult::allowed(),
                        _ => PolicyResult::denied(
                            &policy.id,
                            format!(
                                "invalid timestamp in expiry check: ctx={}, rule={}",
                                context.timestamp, timestamp
                            ),
                        ),
                    }
                }
            };

            if !result.allow {
                return result;
            }
        }
    }

    PolicyResult::allowed()
}

fn load_policies_for_key(key: &ApiKeyFile, policies: &[Policy]) -> WebResult<Vec<Policy>> {
    key.policy_ids
        .iter()
        .map(|id| find_policy(policies, id).cloned())
        .collect()
}

fn policy_denied(result: PolicyResult) -> WebError {
    WebError::new(
        "POLICY_DENIED",
        result.reason.unwrap_or_else(|| "denied".to_string()),
    )
}

fn enforce_policy_and_decrypt_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &Chain,
    policy_raw_hex: String,
    index: u32,
    now_iso: &str,
    wallets: &[EncryptedWallet],
    keys: &[ApiKeyFile],
    policies: &[Policy],
) -> WebResult<SecretBytes> {
    let key_file = find_api_key_by_token(keys, token)?;
    check_expiry(key_file, now_iso)?;

    let wallet = find_wallet(wallets, wallet_name_or_id)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(invalid_input(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id
        )));
    }

    let attached_policies = load_policies_for_key(key_file, policies)?;
    let context = ows_core::PolicyContext {
        api_key_id: key_file.id.clone(),
        chain_id: chain.chain_id.to_string(),
        spending: ows_core::policy::SpendingContext {
            daily_total: "0".to_string(),
            date: date_from_timestamp(now_iso),
        },
        timestamp: now_iso.to_string(),
        transaction: ows_core::policy::TransactionContext {
            data: None,
            raw_hex: policy_raw_hex,
            to: None,
            value: None,
        },
        typed_data: None,
        wallet_id: wallet.id.clone(),
    };

    let result = evaluate_policies(&attached_policies, &context);
    if !result.allow {
        return Err(policy_denied(result));
    }

    decrypt_key_from_api_key(key_file, wallet, token, chain.chain_type, index)
}

fn decrypt_key_from_api_key(
    key: &ApiKeyFile,
    wallet: &EncryptedWallet,
    token: &str,
    chain_type: ChainType,
    index: u32,
) -> WebResult<SecretBytes> {
    let envelope_value = key.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        invalid_input(format!(
            "API key has no encrypted secret for wallet {}",
            wallet.id
        ))
    })?;
    let envelope: CryptoEnvelope = serde_json::from_value(envelope_value.clone())?;
    let secret = decrypt(&envelope, token).map_err(crypto_error)?;
    secret_to_signing_key(&secret, &wallet.key_type, chain_type, index)
}

fn create_wallet_impl(
    name: &str,
    passphrase: &str,
    words: u32,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> WebResult<WalletWriteResult> {
    let wallets = parse_wallets(wallets_json)?;
    ensure_wallet_name_available(&wallets, name)?;

    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(invalid_input("words must be 12 or 24")),
    };
    let mnemonic = Mnemonic::generate(strength)?;
    let accounts = derive_all_accounts(&mnemonic, 0)?;
    let phrase = mnemonic.phrase();
    let envelope = encrypt(phrase.expose(), passphrase).map_err(crypto_error)?;
    let wallet = encrypted_wallet(
        wallet_id.to_string(),
        name.to_string(),
        accounts,
        serde_json::to_value(&envelope)?,
        KeyType::Mnemonic,
        created_at.to_string(),
    );

    Ok(WalletWriteResult {
        info: wallet_to_info(&wallet),
        wallet,
    })
}

fn import_wallet_mnemonic_impl(
    name: &str,
    mnemonic_phrase: &str,
    passphrase: &str,
    index: u32,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> WebResult<WalletWriteResult> {
    let wallets = parse_wallets(wallets_json)?;
    ensure_wallet_name_available(&wallets, name)?;

    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let accounts = derive_all_accounts(&mnemonic, index)?;
    let phrase = mnemonic.phrase();
    let envelope = encrypt(phrase.expose(), passphrase).map_err(crypto_error)?;
    let wallet = encrypted_wallet(
        wallet_id.to_string(),
        name.to_string(),
        accounts,
        serde_json::to_value(&envelope)?,
        KeyType::Mnemonic,
        created_at.to_string(),
    );

    Ok(WalletWriteResult {
        info: wallet_to_info(&wallet),
        wallet,
    })
}

#[allow(clippy::too_many_arguments)]
fn import_wallet_private_key_impl(
    name: &str,
    private_key_hex: &str,
    passphrase: &str,
    chain: &str,
    secp256k1_key_hex: &str,
    ed25519_key_hex: &str,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> WebResult<WalletWriteResult> {
    let wallets = parse_wallets(wallets_json)?;
    ensure_wallet_name_available(&wallets, name)?;

    let secp256k1_key = (!secp256k1_key_hex.is_empty()).then_some(secp256k1_key_hex);
    let ed25519_key = (!ed25519_key_hex.is_empty()).then_some(ed25519_key_hex);

    let keys = match (secp256k1_key, ed25519_key) {
        (Some(secp256k1_key), Some(ed25519_key)) => KeyPair {
            ed25519: decode_hex_key(ed25519_key)?,
            secp256k1: decode_hex_key(secp256k1_key)?,
        },
        _ => {
            let key_bytes = decode_hex_key(private_key_hex)?;
            let source_curve = if chain.is_empty() {
                Curve::Secp256k1
            } else {
                let parsed = parse_chain(chain)?;
                signer_for_chain(parsed.chain_type).curve()
            };

            let mut other_key = vec![0u8; 32];
            getrandom::getrandom(&mut other_key)
                .map_err(|e| invalid_input(format!("failed to generate random key: {e}")))?;

            match source_curve {
                Curve::Ed25519 => KeyPair {
                    ed25519: key_bytes,
                    secp256k1: secp256k1_key
                        .map(decode_hex_key)
                        .transpose()?
                        .unwrap_or(other_key),
                },
                Curve::Secp256k1 => KeyPair {
                    ed25519: ed25519_key
                        .map(decode_hex_key)
                        .transpose()?
                        .unwrap_or(other_key),
                    secp256k1: key_bytes,
                },
            }
        }
    };

    let accounts = derive_all_accounts_from_keys(&keys)?;
    let envelope = encrypt(&keys.to_json_bytes(), passphrase).map_err(crypto_error)?;
    let wallet = encrypted_wallet(
        wallet_id.to_string(),
        name.to_string(),
        accounts,
        serde_json::to_value(&envelope)?,
        KeyType::PrivateKey,
        created_at.to_string(),
    );

    Ok(WalletWriteResult {
        info: wallet_to_info(&wallet),
        wallet,
    })
}

fn sign_transaction_impl(
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let wallets = parse_wallets(wallets_json)?;
    let chain = parse_chain(chain)?;
    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| invalid_input(format!("invalid hex transaction: {e}")))?;

    let key = if credential.starts_with(TOKEN_PREFIX) {
        let keys = parse_keys(keys_json)?;
        let policies = parse_policies(policies_json)?;
        enforce_policy_and_decrypt_key(
            credential,
            wallet_name_or_id,
            &chain,
            hex::encode(&tx_bytes),
            index,
            now_iso,
            &wallets,
            &keys,
            &policies,
        )?
    } else {
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        decrypt_signing_key(wallet, chain.chain_type, credential, index)?
    };

    let signer = signer_for_chain(chain.chain_type);
    let signable = signer.extract_signable_bytes(&tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    Ok(SignResult {
        recovery_id: output.recovery_id,
        signature: hex::encode(output.signature),
    })
}

fn sign_hash_impl(
    wallet_name_or_id: &str,
    chain: &str,
    hash_hex: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let wallets = parse_wallets(wallets_json)?;
    let chain = parse_chain(chain)?;
    let signer = signer_for_chain(chain.chain_type);
    if signer.curve() != Curve::Secp256k1 {
        return Err(invalid_input(
            "raw hash signing is only supported for secp256k1-backed chains",
        ));
    }

    let hash_hex_clean = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
    let hash =
        hex::decode(hash_hex_clean).map_err(|e| invalid_input(format!("invalid hex hash: {e}")))?;
    if hash.len() != 32 {
        return Err(invalid_input(format!(
            "raw hash signing requires exactly 32 bytes, got {}",
            hash.len()
        )));
    }

    let key = if credential.starts_with(TOKEN_PREFIX) {
        let keys = parse_keys(keys_json)?;
        let policies = parse_policies(policies_json)?;
        enforce_policy_and_decrypt_key(
            credential,
            wallet_name_or_id,
            &chain,
            hex::encode(&hash),
            index,
            now_iso,
            &wallets,
            &keys,
            &policies,
        )?
    } else {
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        decrypt_signing_key(wallet, chain.chain_type, credential, index)?
    };

    let output = signer.sign(key.expose(), &hash)?;
    Ok(SignResult {
        recovery_id: output.recovery_id,
        signature: hex::encode(output.signature),
    })
}

fn sign_authorization_impl(
    wallet_name_or_id: &str,
    chain: &str,
    address: &str,
    nonce: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let chain_info = parse_chain(chain)?;
    if chain_info.chain_type != ChainType::Evm {
        return Err(invalid_input(
            "EIP-7702 authorization signing is only supported for EVM chains",
        ));
    }

    let evm_signer = ows_signer::chains::EvmSigner;
    let chain_id = chain_info.evm_chain_reference().map_err(invalid_input)?;
    let payload = evm_signer.authorization_payload(chain_id, address, nonce)?;
    let hash = evm_signer.authorization_hash(chain_id, address, nonce)?;
    sign_hash_with_policy_bytes_impl(
        wallet_name_or_id,
        &chain_info,
        &payload,
        &hash,
        credential,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    )
}

#[allow(clippy::too_many_arguments)]
fn sign_hash_with_policy_bytes_impl(
    wallet_name_or_id: &str,
    chain: &Chain,
    policy_bytes: &[u8],
    hash: &[u8],
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let wallets = parse_wallets(wallets_json)?;
    let signer = signer_for_chain(chain.chain_type);

    let key = if credential.starts_with(TOKEN_PREFIX) {
        let keys = parse_keys(keys_json)?;
        let policies = parse_policies(policies_json)?;
        enforce_policy_and_decrypt_key(
            credential,
            wallet_name_or_id,
            chain,
            hex::encode(policy_bytes),
            index,
            now_iso,
            &wallets,
            &keys,
            &policies,
        )?
    } else {
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        decrypt_signing_key(wallet, chain.chain_type, credential, index)?
    };

    let output = signer.sign(key.expose(), hash)?;
    Ok(SignResult {
        recovery_id: output.recovery_id,
        signature: hex::encode(output.signature),
    })
}

fn sign_message_impl(
    wallet_name_or_id: &str,
    chain: &str,
    message: &str,
    credential: &str,
    encoding: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let wallets = parse_wallets(wallets_json)?;
    let chain = parse_chain(chain)?;
    let msg_bytes = match encoding {
        "hex" => {
            hex::decode(message).map_err(|e| invalid_input(format!("invalid hex message: {e}")))?
        }
        "utf8" => message.as_bytes().to_vec(),
        _ => {
            return Err(invalid_input(format!(
                "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
            )))
        }
    };

    let key = if credential.starts_with(TOKEN_PREFIX) {
        let keys = parse_keys(keys_json)?;
        let policies = parse_policies(policies_json)?;
        enforce_policy_and_decrypt_key(
            credential,
            wallet_name_or_id,
            &chain,
            hex::encode(&msg_bytes),
            index,
            now_iso,
            &wallets,
            &keys,
            &policies,
        )?
    } else {
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        decrypt_signing_key(wallet, chain.chain_type, credential, index)?
    };

    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_message(key.expose(), &msg_bytes)?;
    Ok(SignResult {
        recovery_id: output.recovery_id,
        signature: hex::encode(output.signature),
    })
}

fn sign_typed_data_impl(
    wallet_name_or_id: &str,
    chain: &str,
    typed_data_json: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> WebResult<SignResult> {
    let wallets = parse_wallets(wallets_json)?;
    let chain = parse_chain(chain)?;
    if chain.chain_type != ChainType::Evm {
        return Err(invalid_input(
            "EIP-712 typed data signing is only supported for EVM chains",
        ));
    }

    let parsed = eip712::parse_typed_data(typed_data_json)?;
    if let Some(domain_chain_id) = parsed.domain.get("chainId").and_then(parse_domain_chain_id) {
        let expected_chain_id = chain.evm_chain_id_u64().map_err(invalid_input)?;
        if expected_chain_id != domain_chain_id {
            return Err(invalid_input(format!(
                "EIP-712 domain chainId ({domain_chain_id}) does not match requested chain ({})",
                chain.chain_id
            )));
        }
    }

    let key = if credential.starts_with(TOKEN_PREFIX) {
        let keys = parse_keys(keys_json)?;
        let policies = parse_policies(policies_json)?;
        let key_file = find_api_key_by_token(&keys, credential)?;
        check_expiry(key_file, now_iso)?;
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        if !key_file.wallet_ids.contains(&wallet.id) {
            return Err(invalid_input(format!(
                "API key '{}' does not have access to wallet '{}'",
                key_file.name, wallet.id
            )));
        }

        let typed_data = ows_core::policy::TypedDataContext {
            domain_chain_id: parsed.domain.get("chainId").and_then(parse_domain_chain_id),
            domain_name: parsed
                .domain
                .get("name")
                .and_then(|value| value.as_str())
                .map(String::from),
            domain_version: parsed
                .domain
                .get("version")
                .and_then(|value| value.as_str())
                .map(String::from),
            primary_type: parsed.primary_type.clone(),
            raw_json: typed_data_json.to_string(),
            verifying_contract: parsed
                .domain
                .get("verifyingContract")
                .and_then(|value| value.as_str())
                .map(String::from),
        };

        let attached_policies = load_policies_for_key(key_file, &policies)?;
        let context = ows_core::PolicyContext {
            api_key_id: key_file.id.clone(),
            chain_id: chain.chain_id.to_string(),
            spending: ows_core::policy::SpendingContext {
                daily_total: "0".to_string(),
                date: date_from_timestamp(now_iso),
            },
            timestamp: now_iso.to_string(),
            transaction: ows_core::policy::TransactionContext {
                data: None,
                raw_hex: String::new(),
                to: None,
                value: None,
            },
            typed_data: Some(typed_data),
            wallet_id: wallet.id.clone(),
        };

        let result = evaluate_policies(&attached_policies, &context);
        if !result.allow {
            return Err(policy_denied(result));
        }

        decrypt_key_from_api_key(key_file, wallet, credential, chain.chain_type, index)?
    } else {
        let wallet = find_wallet(&wallets, wallet_name_or_id)?;
        decrypt_signing_key(wallet, chain.chain_type, credential, index)?
    };

    let evm_signer = ows_signer::chains::EvmSigner;
    let output = evm_signer.sign_typed_data(key.expose(), typed_data_json)?;
    Ok(SignResult {
        recovery_id: output.recovery_id,
        signature: hex::encode(output.signature),
    })
}

#[wasm_bindgen(js_name = createApiKey)]
pub fn create_api_key(
    name: &str,
    wallet_ids_json: &str,
    policy_ids_json: &str,
    passphrase: &str,
    expires_at: &str,
    token: &str,
    key_id: &str,
    created_at: &str,
    wallets_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result((|| {
        let wallet_refs: Vec<String> = parse_json(wallet_ids_json, "wallet IDs")?;
        let policy_ids: Vec<String> = parse_json(policy_ids_json, "policy IDs")?;
        let wallets = parse_wallets(wallets_json)?;
        let policies = parse_policies(policies_json)?;
        let mut resolved_wallet_ids = Vec::with_capacity(wallet_refs.len());
        let mut wallet_secrets = HashMap::new();

        for wallet_ref in wallet_refs {
            let wallet = find_wallet(&wallets, &wallet_ref)?;
            let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
            let secret = decrypt(&envelope, passphrase).map_err(crypto_error)?;
            let hkdf_envelope = encrypt_with_hkdf(secret.expose(), token).map_err(crypto_error)?;
            wallet_secrets.insert(wallet.id.clone(), serde_json::to_value(&hkdf_envelope)?);
            resolved_wallet_ids.push(wallet.id.clone());
        }

        for policy_id in &policy_ids {
            let policy = find_policy(&policies, policy_id)?;
            reject_executable_policy(policy)?;
        }

        let key = ApiKeyFile {
            created_at: created_at.to_string(),
            expires_at: (!expires_at.is_empty()).then(|| expires_at.to_string()),
            id: key_id.to_string(),
            name: name.to_string(),
            policy_ids,
            token_hash: hash_token(token),
            wallet_ids: resolved_wallet_ids,
            wallet_secrets,
        };

        Ok(ApiKeyResult {
            id: key.id.clone(),
            key,
            name: name.to_string(),
            token: token.to_string(),
        })
    })())
}

#[wasm_bindgen(js_name = createPolicy)]
pub fn create_policy(policy_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let policy: Policy = parse_json(policy_json, "policy")?;
        reject_executable_policy(&policy)?;
        Ok(policy)
    })())
}

#[wasm_bindgen(js_name = createWallet)]
pub fn create_wallet(
    name: &str,
    passphrase: &str,
    words: u32,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> Result<String, JsValue> {
    json_result(create_wallet_impl(
        name,
        passphrase,
        words,
        wallets_json,
        wallet_id,
        created_at,
    ))
}

#[wasm_bindgen(js_name = deletePolicy)]
pub fn delete_policy(id: &str, policies_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let policies = parse_policies(policies_json)?;
        find_policy(&policies, id)?;
        Ok(DeleteResult { id: id.to_string() })
    })())
}

#[wasm_bindgen(js_name = deleteWallet)]
pub fn delete_wallet(name_or_id: &str, wallets_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let wallets = parse_wallets(wallets_json)?;
        let wallet = find_wallet(&wallets, name_or_id)?;
        Ok(DeleteResult {
            id: wallet.id.clone(),
        })
    })())
}

#[wasm_bindgen(js_name = deriveAddress)]
pub fn derive_address(mnemonic_phrase: &str, chain: &str, index: u32) -> Result<String, JsValue> {
    string_result((|| {
        let chain = parse_chain(chain)?;
        let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
        let signer = signer_for_chain(chain.chain_type);
        let path = signer.default_derivation_path(index);
        let key = HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, signer.curve())?;
        Ok(signer.derive_address(key.expose())?)
    })())
}

#[wasm_bindgen(js_name = exportWallet)]
pub fn export_wallet(
    name_or_id: &str,
    passphrase: &str,
    wallets_json: &str,
) -> Result<String, JsValue> {
    string_result((|| {
        let wallets = parse_wallets(wallets_json)?;
        let wallet = find_wallet(&wallets, name_or_id)?;
        let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;
        let secret = decrypt(&envelope, passphrase).map_err(crypto_error)?;
        String::from_utf8(secret.expose().to_vec())
            .map_err(|_| invalid_input("wallet contains invalid secret data"))
    })())
}

#[wasm_bindgen(js_name = generateMnemonic)]
pub fn generate_mnemonic(words: u32) -> Result<String, JsValue> {
    string_result((|| {
        let strength = match words {
            12 => MnemonicStrength::Words12,
            24 => MnemonicStrength::Words24,
            _ => return Err(invalid_input("words must be 12 or 24")),
        };
        let mnemonic = Mnemonic::generate(strength)?;
        String::from_utf8(mnemonic.phrase().expose().to_vec())
            .map_err(|e| invalid_input(format!("invalid UTF-8 in mnemonic: {e}")))
    })())
}

#[wasm_bindgen(js_name = getPolicy)]
pub fn get_policy(id: &str, policies_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let policies = parse_policies(policies_json)?;
        let policy = find_policy(&policies, id)?;
        Ok(policy.clone())
    })())
}

#[wasm_bindgen(js_name = getWallet)]
pub fn get_wallet(name_or_id: &str, wallets_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let wallets = parse_wallets(wallets_json)?;
        let wallet = find_wallet(&wallets, name_or_id)?;
        Ok(wallet_to_info(wallet))
    })())
}

#[wasm_bindgen(js_name = importWalletMnemonic)]
pub fn import_wallet_mnemonic(
    name: &str,
    mnemonic_phrase: &str,
    passphrase: &str,
    index: u32,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> Result<String, JsValue> {
    json_result(import_wallet_mnemonic_impl(
        name,
        mnemonic_phrase,
        passphrase,
        index,
        wallets_json,
        wallet_id,
        created_at,
    ))
}

#[wasm_bindgen(js_name = importWalletPrivateKey)]
pub fn import_wallet_private_key(
    name: &str,
    private_key_hex: &str,
    passphrase: &str,
    chain: &str,
    secp256k1_key_hex: &str,
    ed25519_key_hex: &str,
    wallets_json: &str,
    wallet_id: &str,
    created_at: &str,
) -> Result<String, JsValue> {
    json_result(import_wallet_private_key_impl(
        name,
        private_key_hex,
        passphrase,
        chain,
        secp256k1_key_hex,
        ed25519_key_hex,
        wallets_json,
        wallet_id,
        created_at,
    ))
}

#[wasm_bindgen(js_name = listApiKeys)]
pub fn list_api_keys(keys_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let mut keys = parse_keys(keys_json)?;
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(keys.iter().map(public_api_key).collect::<Vec<_>>())
    })())
}

#[wasm_bindgen(js_name = listPolicies)]
pub fn list_policies(policies_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let mut policies = parse_policies(policies_json)?;
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    })())
}

#[wasm_bindgen(js_name = listWallets)]
pub fn list_wallets(wallets_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let mut wallets = parse_wallets(wallets_json)?;
        wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(wallets.iter().map(wallet_to_info).collect::<Vec<_>>())
    })())
}

#[wasm_bindgen(js_name = renameWallet)]
pub fn rename_wallet(
    name_or_id: &str,
    new_name: &str,
    wallets_json: &str,
) -> Result<String, JsValue> {
    json_result((|| {
        let mut wallets = parse_wallets(wallets_json)?;
        let index = find_wallet_index(&wallets, name_or_id)?;
        if wallets[index].name != new_name {
            ensure_wallet_name_available(&wallets, new_name)?;
            wallets[index].name = new_name.to_string();
        }
        Ok(WalletWriteResult {
            info: wallet_to_info(&wallets[index]),
            wallet: wallets[index].clone(),
        })
    })())
}

#[wasm_bindgen(js_name = revokeApiKey)]
pub fn revoke_api_key(id: &str, keys_json: &str) -> Result<String, JsValue> {
    json_result((|| {
        let keys = parse_keys(keys_json)?;
        if !keys.iter().any(|key| key.id == id) {
            return Err(WebError::new("API_KEY_NOT_FOUND", "API key not found"));
        }
        Ok(DeleteResult { id: id.to_string() })
    })())
}

#[wasm_bindgen(js_name = signAuthorization)]
pub fn sign_authorization(
    wallet_name_or_id: &str,
    chain: &str,
    address: &str,
    nonce: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result(sign_authorization_impl(
        wallet_name_or_id,
        chain,
        address,
        nonce,
        credential,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    ))
}

#[wasm_bindgen(js_name = signHash)]
pub fn sign_hash(
    wallet_name_or_id: &str,
    chain: &str,
    hash_hex: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result(sign_hash_impl(
        wallet_name_or_id,
        chain,
        hash_hex,
        credential,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    ))
}

#[wasm_bindgen(js_name = signMessage)]
pub fn sign_message(
    wallet_name_or_id: &str,
    chain: &str,
    message: &str,
    credential: &str,
    encoding: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result(sign_message_impl(
        wallet_name_or_id,
        chain,
        message,
        credential,
        encoding,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    ))
}

#[wasm_bindgen(js_name = signTransaction)]
pub fn sign_transaction(
    wallet_name_or_id: &str,
    chain: &str,
    tx_hex: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result(sign_transaction_impl(
        wallet_name_or_id,
        chain,
        tx_hex,
        credential,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    ))
}

#[wasm_bindgen(js_name = signTypedData)]
pub fn sign_typed_data(
    wallet_name_or_id: &str,
    chain: &str,
    typed_data_json: &str,
    credential: &str,
    index: u32,
    now_iso: &str,
    wallets_json: &str,
    keys_json: &str,
    policies_json: &str,
) -> Result<String, JsValue> {
    json_result(sign_typed_data_impl(
        wallet_name_or_id,
        chain,
        typed_data_json,
        credential,
        index,
        now_iso,
        wallets_json,
        keys_json,
        policies_json,
    ))
}
