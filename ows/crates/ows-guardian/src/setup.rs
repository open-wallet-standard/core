use std::path::Path;

use ows_signer::{decrypt, encrypt, CryptoEnvelope};

use crate::error::GuardianError;
use crate::guardian_store;
use crate::shamir;
use crate::types::{Guardian, GuardianConfig, GuardianInput};

pub fn setup_guardians(
    wallet_id: &str,
    wallet_name: &str,
    wallet_crypto: &serde_json::Value,
    owner_passphrase: &str,
    threshold: u8,
    guardian_inputs: &[GuardianInput],
    _time_lock_hours: u64,
    vault_path: Option<&Path>,
) -> Result<GuardianConfig, GuardianError> {
    let total = guardian_inputs.len() as u8;

    if threshold < 2 {
        return Err(GuardianError::InvalidThreshold(
            "threshold must be at least 2".into(),
        ));
    }
    if threshold > total {
        return Err(GuardianError::InvalidThreshold(format!(
            "threshold ({}) exceeds guardian count ({})",
            threshold, total
        )));
    }

    let envelope: CryptoEnvelope = serde_json::from_value(wallet_crypto.clone()).map_err(|e| {
        GuardianError::Crypto(ows_signer::CryptoError::InvalidParams(e.to_string()))
    })?;
    let secret = decrypt(&envelope, owner_passphrase)?;
    let secret_hash = shamir::hash_secret(secret.expose());

    let shards = shamir::split_secret(secret.expose(), threshold, total)?;

    let mut guardians = Vec::with_capacity(guardian_inputs.len());
    for (i, (input, shard)) in guardian_inputs.iter().zip(shards.iter()).enumerate() {
        let shard_envelope = encrypt(shard, &input.passphrase)?;
        let envelope_json =
            serde_json::to_value(&shard_envelope).map_err(|e| GuardianError::Json(e))?;

        guardians.push(Guardian {
            id: format!("guardian-{}", i + 1),
            name: input.name.clone(),
            can_freeze: input.can_freeze,
            encrypted_shard: envelope_json,
        });
    }

    let config = GuardianConfig {
        wallet_id: wallet_id.to_string(),
        wallet_name: wallet_name.to_string(),
        threshold,
        total_guardians: total,
        secret_hash,
        guardians,
        created_at: chrono::Utc::now().to_rfc3339(),
        dead_mans_switch: None,
    };

    guardian_store::save_guardian_config(&config, vault_path)?;

    Ok(config)
}

pub fn guardian_status(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<GuardianConfig, GuardianError> {
    guardian_store::load_guardian_config(wallet_id, vault_path)
}
