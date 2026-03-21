pub mod config;
pub mod derive;
pub mod generate;
pub mod info;
pub mod send_transaction;
pub mod sign_message;
pub mod sign_transaction;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::CliError;
use ows_signer::process_hardening::clear_env_var;
use std::io::{self, BufRead, IsTerminal, Write};
use zeroize::Zeroizing;

/// Read mnemonic from OWS_MNEMONIC env var (or LWS_MNEMONIC fallback) or stdin.
pub fn read_mnemonic() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) = clear_env_var("OWS_MNEMONIC").or_else(|| clear_env_var("LWS_MNEMONIC")) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set OWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}

/// Read a hex-encoded private key from OWS_PRIVATE_KEY env var (or LWS_PRIVATE_KEY fallback) or stdin.
pub fn read_private_key() -> Result<Zeroizing<String>, CliError> {
    if let Some(value) =
        clear_env_var("OWS_PRIVATE_KEY").or_else(|| clear_env_var("LWS_PRIVATE_KEY"))
    {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(Zeroizing::new(trimmed));
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no private key provided (set OWS_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    Ok(Zeroizing::new(trimmed))
}
