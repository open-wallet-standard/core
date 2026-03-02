pub mod derive;
pub mod generate;
pub mod info;
pub mod sign;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::CliError;
use lws_signer::process_hardening::clear_env_var;
use std::io::{self, BufRead, IsTerminal, Write};

/// Read mnemonic from LWS_MNEMONIC env var or stdin. Clears the env var after reading.
pub fn read_mnemonic() -> Result<String, CliError> {
    if let Some(value) = clear_env_var("LWS_MNEMONIC") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
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
            "no mnemonic provided (set LWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(trimmed)
}
