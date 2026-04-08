use std::collections::HashMap;
use std::path::Path;

use ows_core::{ApiKeyFile, EncryptedWallet, OwsError};
use ows_signer::{decrypt, encrypt_with_hkdf, signer_for_chain, CryptoEnvelope, SecretBytes};

use crate::error::OwsLibError;
use crate::key_store;
use crate::policy_engine;
use crate::policy_store;
use crate::vault;

/// Create an API key for agent access to one or more wallets.
///
/// 1. Authenticates with the owner's passphrase
/// 2. Decrypts the wallet secret for each wallet
/// 3. Generates a random token (`ows_key_...`)
/// 4. Re-encrypts each secret under HKDF(token)
/// 5. Stores the key file with token hash, policy IDs, and encrypted copies
/// 6. Returns the raw token (shown once to the user)
pub fn create_api_key(
    name: &str,
    wallet_ids: &[String],
    policy_ids: &[String],
    passphrase: &str,
    expires_at: Option<&str>,
    vault_path: Option<&Path>,
) -> Result<(String, ApiKeyFile), OwsLibError> {
    // Validate that all wallets exist and passphrase works
    let mut wallet_secrets = HashMap::new();
    let mut resolved_wallet_ids = Vec::with_capacity(wallet_ids.len());
    let token = key_store::generate_token();

    for wallet_id in wallet_ids {
        let wallet = vault::load_wallet_by_name_or_id(wallet_id, vault_path)?;
        let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;

        // Decrypt with owner's passphrase to verify it works
        let secret = decrypt(&envelope, passphrase)?;

        // Re-encrypt under HKDF(token)
        let hkdf_envelope = encrypt_with_hkdf(secret.expose(), &token)?;
        let envelope_json = serde_json::to_value(&hkdf_envelope)?;

        wallet_secrets.insert(wallet.id.clone(), envelope_json);
        // Always persist canonical wallet IDs (UUIDs). Callers may pass names or IDs;
        // agent signing checks `contains(wallet.id)` when verifying scope.
        resolved_wallet_ids.push(wallet.id.clone());
    }

    // Validate that all policies exist
    for policy_id in policy_ids {
        policy_store::load_policy(policy_id, vault_path)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let key_file = ApiKeyFile {
        id,
        name: name.to_string(),
        token_hash: key_store::hash_token(&token),
        created_at: chrono::Utc::now().to_rfc3339(),
        wallet_ids: resolved_wallet_ids,
        policy_ids: policy_ids.to_vec(),
        expires_at: expires_at.map(String::from),
        wallet_secrets,
    };

    key_store::save_api_key(&key_file, vault_path)?;

    Ok((token, key_file))
}

/// Sign a transaction using an API token (agent mode).
///
/// 1. Look up key file by SHA256(token)
/// 2. Check expiry and wallet scope
/// 3. Load and evaluate policies
/// 4. HKDF(token) → decrypt wallet secret
/// 5. Resolve signing key → sign
pub fn sign_with_api_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &ows_core::Chain,
    tx_bytes: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<crate::types::SignResult, OwsLibError> {
    // 1. Look up key file
    let token_hash = key_store::hash_token(token);
    let key_file = key_store::load_api_key_by_token_hash(&token_hash, vault_path)?;

    // 2. Check expiry
    check_expiry(&key_file)?;

    // 3. Resolve wallet and check scope
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(OwsLibError::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id,
        )));
    }

    // 4. Load policies and build context
    let policies = load_policies_for_key(&key_file, vault_path)?;
    let now = chrono::Utc::now();
    let date = now.format("%Y-%m-%d").to_string();

    let tx_hex = hex::encode(tx_bytes);

    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: tx_hex,
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
    };

    // 5. Evaluate policies
    let result = policy_engine::evaluate_policies(&policies, &context);
    if !result.allow {
        return Err(OwsLibError::Core(OwsError::PolicyDenied {
            policy_id: result.policy_id.unwrap_or_default(),
            reason: result.reason.unwrap_or_else(|| "denied".into()),
        }));
    }

    // 6. Decrypt wallet secret from key file using HKDF(token)
    let key = decrypt_key_from_api_key(&key_file, &wallet, token, chain.chain_type, index)?;

    // 7. Sign (extract signable portion first — e.g. strips Solana sig-slot headers)
    let signer = signer_for_chain(chain.chain_type);
    let signable = signer.extract_signable_bytes(tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    Ok(crate::types::SignResult {
        signature: hex::encode(&output.signature),
        recovery_id: output.recovery_id,
    })
}

/// Sign a message using an API token (agent mode).
pub fn sign_message_with_api_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &ows_core::Chain,
    msg_bytes: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<crate::types::SignResult, OwsLibError> {
    let token_hash = key_store::hash_token(token);
    let key_file = key_store::load_api_key_by_token_hash(&token_hash, vault_path)?;

    check_expiry(&key_file)?;

    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(OwsLibError::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id,
        )));
    }

    let policies = load_policies_for_key(&key_file, vault_path)?;
    let now = chrono::Utc::now();
    let date = now.format("%Y-%m-%d").to_string();

    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: hex::encode(msg_bytes),
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
    };

    let result = policy_engine::evaluate_policies(&policies, &context);
    if !result.allow {
        return Err(OwsLibError::Core(OwsError::PolicyDenied {
            policy_id: result.policy_id.unwrap_or_default(),
            reason: result.reason.unwrap_or_else(|| "denied".into()),
        }));
    }

    let key = decrypt_key_from_api_key(&key_file, &wallet, token, chain.chain_type, index)?;
    let signer = signer_for_chain(chain.chain_type);
    let output = signer.sign_message(key.expose(), msg_bytes)?;

    Ok(crate::types::SignResult {
        signature: hex::encode(&output.signature),
        recovery_id: output.recovery_id,
    })
}

/// Enforce policies for a token-based transaction and return the decrypted
/// signing key. Used by `sign_and_send` which needs the raw key for broadcast.
pub fn enforce_policy_and_decrypt_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &ows_core::Chain,
    tx_bytes: &[u8],
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<(SecretBytes, ApiKeyFile), OwsLibError> {
    let token_hash = key_store::hash_token(token);
    let key_file = key_store::load_api_key_by_token_hash(&token_hash, vault_path)?;
    check_expiry(&key_file)?;

    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(OwsLibError::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id,
        )));
    }

    let policies = load_policies_for_key(&key_file, vault_path)?;
    let now = chrono::Utc::now();
    let date = now.format("%Y-%m-%d").to_string();

    let tx_hex = hex::encode(tx_bytes);

    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: tx_hex,
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
    };

    let result = policy_engine::evaluate_policies(&policies, &context);
    if !result.allow {
        return Err(OwsLibError::Core(OwsError::PolicyDenied {
            policy_id: result.policy_id.unwrap_or_default(),
            reason: result.reason.unwrap_or_else(|| "denied".into()),
        }));
    }

    let key = decrypt_key_from_api_key(&key_file, &wallet, token, chain.chain_type, index)?;

    Ok((key, key_file))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn noop_spending_context(date: &str) -> ows_core::policy::SpendingContext {
    ows_core::policy::SpendingContext {
        daily_total: "0".to_string(),
        date: date.to_string(),
    }
}

fn check_expiry(key_file: &ApiKeyFile) -> Result<(), OwsLibError> {
    if let Some(ref expires) = key_file.expires_at {
        let now = chrono::Utc::now();
        let exp = chrono::DateTime::parse_from_rfc3339(expires).map_err(|e| {
            OwsLibError::Core(OwsError::InvalidInput {
                message: format!("invalid expires_at timestamp '{}': {}", expires, e),
            })
        })?;
        if now > exp {
            return Err(OwsLibError::Core(OwsError::ApiKeyExpired {
                id: key_file.id.clone(),
            }));
        }
    }
    Ok(())
}

fn load_policies_for_key(
    key_file: &ApiKeyFile,
    vault_path: Option<&Path>,
) -> Result<Vec<ows_core::Policy>, OwsLibError> {
    let mut policies = Vec::with_capacity(key_file.policy_ids.len());
    for pid in &key_file.policy_ids {
        policies.push(policy_store::load_policy(pid, vault_path)?);
    }
    Ok(policies)
}

fn decrypt_key_from_api_key(
    key_file: &ApiKeyFile,
    wallet: &EncryptedWallet,
    token: &str,
    chain_type: ows_core::ChainType,
    index: Option<u32>,
) -> Result<SecretBytes, OwsLibError> {
    let envelope_value = key_file.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        OwsLibError::InvalidInput(format!(
            "API key has no encrypted secret for wallet {}",
            wallet.id
        ))
    })?;

    let envelope: CryptoEnvelope = serde_json::from_value(envelope_value.clone())?;
    let secret = decrypt(&envelope, token)?;
    crate::ops::secret_to_signing_key(&secret, &wallet.key_type, chain_type, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_core::{EncryptedWallet, KeyType, PolicyAction, PolicyRule, WalletAccount};
    use ows_signer::encrypt;

    /// Create a test wallet in the vault, return its ID.
    fn setup_test_wallet(vault: &Path, passphrase: &str) -> String {
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let envelope = encrypt(mnemonic_phrase.as_bytes(), passphrase).unwrap();
        let crypto = serde_json::to_value(&envelope).unwrap();

        let wallet = EncryptedWallet::new(
            "test-wallet-id".to_string(),
            "test-wallet".to_string(),
            vec![WalletAccount {
                account_id: "eip155:8453:0xabc".to_string(),
                address: "0xabc".to_string(),
                chain_id: "eip155:8453".to_string(),
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
            }],
            crypto,
            KeyType::Mnemonic,
        );

        vault::save_encrypted_wallet(&wallet, Some(vault)).unwrap();
        wallet.id
    }

    fn setup_test_policy(vault: &Path) -> String {
        let policy = ows_core::Policy {
            id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![PolicyRule::AllowedChains {
                chain_ids: vec!["eip155:8453".to_string()],
            }],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };
        policy_store::save_policy(&policy, Some(vault)).unwrap();
        policy.id
    }

    #[test]
    fn create_api_key_and_verify_token() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, key_file) = create_api_key(
            "test-agent",
            std::slice::from_ref(&wallet_id),
            std::slice::from_ref(&policy_id),
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        // Token has correct format
        assert!(token.starts_with("ows_key_"));

        // Key file has correct data
        assert_eq!(key_file.name, "test-agent");
        assert_eq!(key_file.wallet_ids, vec![wallet_id.clone()]);
        assert_eq!(key_file.policy_ids, vec![policy_id]);
        assert_eq!(key_file.token_hash, key_store::hash_token(&token));
        assert!(key_file.expires_at.is_none());

        // Wallet secret is present and decryptable
        assert!(key_file.wallet_secrets.contains_key(&wallet_id));
        let envelope: CryptoEnvelope =
            serde_json::from_value(key_file.wallet_secrets[&wallet_id].clone()).unwrap();
        let decrypted = decrypt(&envelope, &token).unwrap();
        assert_eq!(
            std::str::from_utf8(decrypted.expose()).unwrap(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );

        // Key is persisted and loadable
        let loaded = key_store::load_api_key(&key_file.id, Some(&vault)).unwrap();
        assert_eq!(loaded.name, "test-agent");
    }

    /// Regression: API key scope must store resolved wallet UUIDs even when the caller passes a
    /// wallet *name* (Node bindings and other callers pass strings that may be names).
    #[test]
    fn create_api_key_accepts_wallet_name_and_stores_canonical_ids() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, key_file) = create_api_key(
            "name-input-agent",
            &["test-wallet".to_string()],
            std::slice::from_ref(&policy_id),
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        assert_eq!(key_file.wallet_ids, vec![wallet_id.clone()]);

        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32];
        let result =
            sign_with_api_key(&token, "test-wallet", &chain, &tx_bytes, None, Some(&vault));
        assert!(
            result.is_ok(),
            "sign_with_api_key failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn create_api_key_wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet_id = setup_test_wallet(&vault, "correct");
        let policy_id = setup_test_policy(&vault);

        let result = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            "wrong-passphrase",
            None,
            Some(&vault),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_api_key_nonexistent_wallet_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let policy_id = setup_test_policy(&vault);

        let result = create_api_key(
            "agent",
            &["nonexistent".to_string()],
            &[policy_id],
            "pass",
            None,
            Some(&vault),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_api_key_nonexistent_policy_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet_id = setup_test_wallet(&vault, "pass");

        let result = create_api_key(
            "agent",
            &[wallet_id],
            &["nonexistent-policy".to_string()],
            "pass",
            None,
            Some(&vault),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_api_key_with_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet_id = setup_test_wallet(&vault, "pass");
        let policy_id = setup_test_policy(&vault);

        let (_, key_file) = create_api_key(
            "expiring-agent",
            &[wallet_id],
            &[policy_id],
            "pass",
            Some("2026-12-31T00:00:00Z"),
            Some(&vault),
        )
        .unwrap();

        assert_eq!(key_file.expires_at.as_deref(), Some("2026-12-31T00:00:00Z"));
    }

    #[test]
    fn sign_with_api_key_full_flow() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "signer-agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        // Sign a dummy transaction on the allowed chain
        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32]; // dummy tx

        let result =
            sign_with_api_key(&token, "test-wallet", &chain, &tx_bytes, None, Some(&vault));

        // The signing should succeed (policy allows eip155:8453)
        assert!(
            result.is_ok(),
            "sign_with_api_key failed: {:?}",
            result.err()
        );
        let sign_result = result.unwrap();
        assert!(!sign_result.signature.is_empty());
    }

    #[test]
    fn imported_private_key_wallet_signs_with_api_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();

        let wallet = crate::import_wallet_private_key(
            "imported-wallet",
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            Some("evm"),
            Some(""),
            Some(&vault),
            None,
            None,
        )
        .unwrap();
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "imported-wallet-agent",
            std::slice::from_ref(&wallet.id),
            std::slice::from_ref(&policy_id),
            "",
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32];

        let tx_result = sign_with_api_key(
            &token,
            "imported-wallet",
            &chain,
            &tx_bytes,
            None,
            Some(&vault),
        );
        assert!(
            tx_result.is_ok(),
            "sign_with_api_key failed: {:?}",
            tx_result.err()
        );
        assert!(!tx_result.unwrap().signature.is_empty());

        let msg_result = sign_message_with_api_key(
            &token,
            "imported-wallet",
            &chain,
            b"hello",
            None,
            Some(&vault),
        );
        assert!(
            msg_result.is_ok(),
            "sign_message_with_api_key failed: {:?}",
            msg_result.err()
        );
        assert!(!msg_result.unwrap().signature.is_empty());
    }

    #[test]
    fn sign_with_api_key_wrong_chain_denied() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault); // allows only eip155:8453

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        // Try to sign on a chain NOT in the policy allowlist
        let chain = ows_core::parse_chain("ethereum").unwrap(); // eip155:1
        let tx_bytes = vec![0u8; 32];

        let result =
            sign_with_api_key(&token, "test-wallet", &chain, &tx_bytes, None, Some(&vault));

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::Core(OwsError::PolicyDenied { reason, .. }) => {
                assert!(reason.contains("not in allowlist"));
            }
            other => panic!("expected PolicyDenied, got: {other}"),
        }
    }

    #[test]
    fn sign_with_api_key_expired_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            Some("2020-01-01T00:00:00Z"), // already expired
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32];

        let result =
            sign_with_api_key(&token, "test-wallet", &chain, &tx_bytes, None, Some(&vault));

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::Core(OwsError::ApiKeyExpired { .. }) => {}
            other => panic!("expected ApiKeyExpired, got: {other}"),
        }
    }

    #[test]
    fn sign_with_wrong_token_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (_token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32];

        let result = sign_with_api_key(
            "ows_key_wrong_token",
            "test-wallet",
            &chain,
            &tx_bytes,
            None,
            Some(&vault),
        );

        assert!(result.is_err());
    }

    #[test]
    fn sign_wallet_not_in_scope_fails() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        // Create two wallets
        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        // Create a second wallet
        let mnemonic2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let envelope2 = encrypt(mnemonic2.as_bytes(), passphrase).unwrap();
        let crypto2 = serde_json::to_value(&envelope2).unwrap();
        let wallet2 = EncryptedWallet::new(
            "wallet-2-id".to_string(),
            "other-wallet".to_string(),
            vec![],
            crypto2,
            KeyType::Mnemonic,
        );
        vault::save_encrypted_wallet(&wallet2, Some(&vault)).unwrap();

        // API key only has access to first wallet
        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let tx_bytes = vec![0u8; 32];

        // Try to sign with the second wallet → should fail
        let result = sign_with_api_key(
            &token,
            "other-wallet",
            &chain,
            &tx_bytes,
            None,
            Some(&vault),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::InvalidInput(msg) => {
                assert!(msg.contains("does not have access"));
            }
            other => panic!("expected InvalidInput, got: {other}"),
        }
    }
}
