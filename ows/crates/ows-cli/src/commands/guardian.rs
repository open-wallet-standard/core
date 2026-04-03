use crate::CliError;
use ows_guardian::types::GuardianInput;
use std::io::{self, BufRead, IsTerminal, Write};

pub fn setup(
    wallet_name: &str,
    threshold: u8,
    guardians_file: &str,
    time_lock_hours: u64,
) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let contents = std::fs::read_to_string(guardians_file).map_err(|e| CliError::Io(e))?;
    let guardian_inputs: Vec<GuardianInput> =
        serde_json::from_str(&contents).map_err(|e| CliError::Json(e))?;

    let encrypted = ows_lib::vault::load_wallet_by_name_or_id(wallet_name, None)
        .map_err(|e| CliError::Lib(e))?;

    let passphrase = super::read_passphrase();

    let config = ows_guardian::setup_guardians(
        &wallet.id,
        &wallet.name,
        &encrypted.crypto,
        &passphrase,
        threshold,
        &guardian_inputs,
        time_lock_hours,
        None,
    )
    .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    print_setup_result(&config);
    Ok(())
}

fn print_setup_result(config: &ows_guardian::GuardianConfig) {
    println!(
        "Guardian recovery configured for wallet: {}",
        config.wallet_name
    );
    println!(
        "Threshold: {}-of-{}",
        config.threshold, config.total_guardians
    );
    println!();
    for g in &config.guardians {
        let freeze_label = if g.can_freeze { " [can freeze]" } else { "" };
        println!("  {} ({}): shard encrypted{}", g.id, g.name, freeze_label);
    }
}

pub fn status(wallet_name: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let config = ows_guardian::guardian_status(&wallet.id, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Wallet:     {} ({})", config.wallet_name, config.wallet_id);
    println!(
        "Threshold:  {}-of-{}",
        config.threshold, config.total_guardians
    );
    println!("Created:    {}", config.created_at);
    println!();
    for g in &config.guardians {
        let freeze = if g.can_freeze { " [freeze]" } else { "" };
        println!("  {} {}{}", g.id, g.name, freeze);
    }

    if let Some(ref dms) = config.dead_mans_switch {
        println!();
        println!("Dead Man's Switch:");
        println!("  Inactivity: {} days", dms.inactivity_days);
        println!("  Last heartbeat: {}", dms.last_heartbeat);
        for b in &dms.beneficiaries {
            println!("  Beneficiary: {} ({})", b.name, b.guardian_id);
        }
    }

    Ok(())
}

pub fn recover_init(
    wallet_name: &str,
    guardian_id: &str,
    time_lock_hours: u64,
) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let request = ows_guardian::initiate_recovery(&wallet.id, guardian_id, time_lock_hours, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Recovery initiated for wallet: {}", wallet_name);
    println!("Time lock until: {}", request.time_lock_until);
    println!("Shards needed: {}", request.threshold);
    Ok(())
}

fn read_guardian_passphrase() -> String {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Guardian passphrase: ");
        io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        line.trim().to_string()
    } else {
        std::env::var("OWS_GUARDIAN_PASSPHRASE").unwrap_or_default()
    }
}

pub fn recover_submit(wallet_name: &str, guardian_id: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let passphrase = read_guardian_passphrase();

    let request = ows_guardian::submit_shard(&wallet.id, guardian_id, &passphrase, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    let have = request.submitted_shards.len();
    let need = request.threshold as usize;
    println!("Shard {}/{} submitted from {}", have, need, guardian_id);
    if have >= need {
        println!("Threshold met! Run `ows guardian recover complete` to finish.");
    }
    Ok(())
}

pub fn recover_complete(wallet_name: &str, new_name: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let secret = ows_guardian::complete_recovery(&wallet.id, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    let secret_str = String::from_utf8_lossy(&secret);

    let info = ows_lib::import_wallet_mnemonic(new_name, &secret_str, None, Some(0), None)
        .map_err(|e| CliError::Lib(e))?;

    println!("Secret reconstructed and verified!");
    println!("Wallet imported as: {} ({})", new_name, info.id);
    println!();
    for acct in &info.accounts {
        println!("  {} -> {}", acct.chain_id, acct.address);
    }
    Ok(())
}

pub fn recover_cancel(wallet_name: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    ows_guardian::cancel_recovery(&wallet.id, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Recovery cancelled for wallet: {}", wallet_name);
    Ok(())
}

pub fn recover_freeze(wallet_name: &str, guardian_id: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let passphrase = read_guardian_passphrase();

    ows_guardian::freeze_recovery(&wallet.id, guardian_id, &passphrase, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Recovery FROZEN by {}", guardian_id);
    Ok(())
}

pub fn recover_status(wallet_name: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let request = ows_guardian::recovery_status(&wallet.id, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Wallet:      {}", wallet_name);
    println!("Status:      {:?}", request.status);
    println!("Initiated:   {}", request.initiated_at);
    println!("Time lock:   {}", request.time_lock_until);
    println!(
        "Shards:      {}/{}",
        request.submitted_shards.len(),
        request.threshold
    );
    for s in &request.submitted_shards {
        println!("  {} at {}", s.guardian_id, s.submitted_at);
    }
    Ok(())
}

pub fn heartbeat(wallet_name: &str) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    ows_guardian::record_heartbeat(&wallet.id, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!("Heartbeat recorded for wallet: {}", wallet_name);
    Ok(())
}

pub fn dead_switch(
    wallet_name: &str,
    inactivity_days: u64,
    beneficiaries_file: &str,
) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None).map_err(|e| CliError::Lib(e))?;

    let contents = std::fs::read_to_string(beneficiaries_file).map_err(|e| CliError::Io(e))?;
    let beneficiaries: Vec<ows_guardian::Beneficiary> =
        serde_json::from_str(&contents).map_err(|e| CliError::Json(e))?;

    ows_guardian::configure_dead_mans_switch(&wallet.id, inactivity_days, beneficiaries, None)
        .map_err(|e| CliError::InvalidArgs(e.to_string()))?;

    println!(
        "Dead man's switch configured: {} day inactivity trigger",
        inactivity_days
    );
    Ok(())
}
