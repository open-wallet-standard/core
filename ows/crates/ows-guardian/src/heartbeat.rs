use std::path::Path;

use crate::error::GuardianError;
use crate::guardian_store;
use crate::types::{Beneficiary, DeadMansSwitchConfig};

pub fn record_heartbeat(wallet_id: &str, vault_path: Option<&Path>) -> Result<(), GuardianError> {
    let mut config = guardian_store::load_guardian_config(wallet_id, vault_path)?;

    if let Some(ref mut dms) = config.dead_mans_switch {
        dms.last_heartbeat = chrono::Utc::now().to_rfc3339();
    } else {
        return Err(GuardianError::ConfigNotFound(format!(
            "no dead man's switch configured for {}",
            wallet_id
        )));
    }

    guardian_store::save_guardian_config(&config, vault_path)?;
    Ok(())
}

pub fn configure_dead_mans_switch(
    wallet_id: &str,
    inactivity_days: u64,
    beneficiaries: Vec<Beneficiary>,
    vault_path: Option<&Path>,
) -> Result<(), GuardianError> {
    let mut config = guardian_store::load_guardian_config(wallet_id, vault_path)?;

    config.dead_mans_switch = Some(DeadMansSwitchConfig {
        inactivity_days,
        last_heartbeat: chrono::Utc::now().to_rfc3339(),
        beneficiaries,
    });

    guardian_store::save_guardian_config(&config, vault_path)?;
    Ok(())
}

pub fn check_heartbeat(wallet_id: &str, vault_path: Option<&Path>) -> Result<bool, GuardianError> {
    let config = guardian_store::load_guardian_config(wallet_id, vault_path)?;

    let dms = config.dead_mans_switch.as_ref().ok_or_else(|| {
        GuardianError::ConfigNotFound(format!("no dead man's switch for {}", wallet_id))
    })?;

    let last = chrono::DateTime::parse_from_rfc3339(&dms.last_heartbeat)
        .map_err(|e| GuardianError::ConfigNotFound(e.to_string()))?;
    let deadline = last + chrono::Duration::days(dms.inactivity_days as i64);
    let now = chrono::Utc::now();

    Ok(now > deadline)
}
