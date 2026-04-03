use std::path::Path;

use ows_signer::{decrypt, CryptoEnvelope};

use crate::error::GuardianError;
use crate::guardian_store;
use crate::recovery_store;
use crate::shamir;
use crate::types::{RecoveryRequest, RecoveryStatus, SubmittedShard};

pub fn initiate_recovery(
    wallet_id: &str,
    guardian_id: &str,
    time_lock_hours: u64,
    vault_path: Option<&Path>,
) -> Result<RecoveryRequest, GuardianError> {
    let config = guardian_store::load_guardian_config(wallet_id, vault_path)?;

    if !config.guardians.iter().any(|g| g.id == guardian_id) {
        return Err(GuardianError::GuardianNotFound(guardian_id.to_string()));
    }

    if let Ok(existing) = recovery_store::load_recovery(wallet_id, vault_path) {
        if existing.status == RecoveryStatus::Pending
            || existing.status == RecoveryStatus::ThresholdMet
        {
            return Err(GuardianError::RecoveryAlreadyActive(wallet_id.to_string()));
        }
    }

    let now = chrono::Utc::now();
    let time_lock_until = now + chrono::Duration::hours(time_lock_hours as i64);

    let request = RecoveryRequest {
        wallet_id: wallet_id.to_string(),
        initiated_by: guardian_id.to_string(),
        initiated_at: now.to_rfc3339(),
        time_lock_until: time_lock_until.to_rfc3339(),
        status: RecoveryStatus::Pending,
        submitted_shards: Vec::new(),
        threshold: config.threshold,
    };

    recovery_store::save_recovery(&request, vault_path)?;
    Ok(request)
}

pub fn submit_shard(
    wallet_id: &str,
    guardian_id: &str,
    guardian_passphrase: &str,
    vault_path: Option<&Path>,
) -> Result<RecoveryRequest, GuardianError> {
    let config = guardian_store::load_guardian_config(wallet_id, vault_path)?;
    let mut request = recovery_store::load_recovery(wallet_id, vault_path)?;

    if request.status == RecoveryStatus::Frozen {
        return Err(GuardianError::RecoveryFrozen(wallet_id.to_string()));
    }
    if request.status != RecoveryStatus::Pending && request.status != RecoveryStatus::ThresholdMet {
        return Err(GuardianError::RecoveryNotFound(wallet_id.to_string()));
    }

    if request
        .submitted_shards
        .iter()
        .any(|s| s.guardian_id == guardian_id)
    {
        return Err(GuardianError::DuplicateShard(guardian_id.to_string()));
    }

    let guardian = config
        .guardians
        .iter()
        .find(|g| g.id == guardian_id)
        .ok_or_else(|| GuardianError::GuardianNotFound(guardian_id.to_string()))?;

    let envelope: CryptoEnvelope = serde_json::from_value(guardian.encrypted_shard.clone())
        .map_err(|e| GuardianError::Json(e))?;
    let shard = decrypt(&envelope, guardian_passphrase)?;

    request.submitted_shards.push(SubmittedShard {
        guardian_id: guardian_id.to_string(),
        shard_data: shard.expose().to_vec(),
        submitted_at: chrono::Utc::now().to_rfc3339(),
    });

    if request.submitted_shards.len() >= request.threshold as usize {
        request.status = RecoveryStatus::ThresholdMet;
    }

    recovery_store::save_recovery(&request, vault_path)?;
    Ok(request)
}

pub fn complete_recovery(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<Vec<u8>, GuardianError> {
    let config = guardian_store::load_guardian_config(wallet_id, vault_path)?;
    let request = recovery_store::load_recovery(wallet_id, vault_path)?;

    if request.status != RecoveryStatus::ThresholdMet {
        return Err(GuardianError::ThresholdNotMet {
            have: request.submitted_shards.len(),
            need: request.threshold as usize,
        });
    }

    let now = chrono::Utc::now();
    let time_lock = chrono::DateTime::parse_from_rfc3339(&request.time_lock_until)
        .map_err(|e| GuardianError::RecoveryNotFound(e.to_string()))?;
    if now < time_lock {
        return Err(GuardianError::TimeLocked(request.time_lock_until.clone()));
    }

    let shard_bytes: Vec<Vec<u8>> = request
        .submitted_shards
        .iter()
        .map(|s| s.shard_data.clone())
        .collect();

    let secret = shamir::reconstruct_secret(&shard_bytes, config.threshold)?;

    let recovered_hash = shamir::hash_secret(&secret);
    if recovered_hash != config.secret_hash {
        return Err(GuardianError::SecretHashMismatch);
    }

    let mut request = request;
    request.status = RecoveryStatus::Completed;
    recovery_store::save_recovery(&request, vault_path)?;

    Ok(secret)
}

pub fn cancel_recovery(wallet_id: &str, vault_path: Option<&Path>) -> Result<(), GuardianError> {
    let mut request = recovery_store::load_recovery(wallet_id, vault_path)?;
    request.status = RecoveryStatus::Cancelled;
    recovery_store::save_recovery(&request, vault_path)?;
    Ok(())
}

pub fn freeze_recovery(
    wallet_id: &str,
    guardian_id: &str,
    guardian_passphrase: &str,
    vault_path: Option<&Path>,
) -> Result<(), GuardianError> {
    let config = guardian_store::load_guardian_config(wallet_id, vault_path)?;

    let guardian = config
        .guardians
        .iter()
        .find(|g| g.id == guardian_id && g.can_freeze)
        .ok_or_else(|| {
            GuardianError::GuardianNotFound(format!("{} (not authorized to freeze)", guardian_id))
        })?;

    let envelope: CryptoEnvelope = serde_json::from_value(guardian.encrypted_shard.clone())
        .map_err(|e| GuardianError::Json(e))?;
    let _shard = decrypt(&envelope, guardian_passphrase)?;

    let mut request = recovery_store::load_recovery(wallet_id, vault_path)?;
    request.status = RecoveryStatus::Frozen;
    recovery_store::save_recovery(&request, vault_path)?;

    Ok(())
}

pub fn recovery_status(
    wallet_id: &str,
    vault_path: Option<&Path>,
) -> Result<RecoveryRequest, GuardianError> {
    recovery_store::load_recovery(wallet_id, vault_path)
}
