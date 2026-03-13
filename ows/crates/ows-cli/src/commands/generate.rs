use ows_signer::{Mnemonic, MnemonicStrength};

use crate::CliError;

pub fn run(words: u32) -> Result<(), CliError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        24 => MnemonicStrength::Words24,
        _ => return Err(CliError::InvalidArgs("--words must be 12 or 24".into())),
    };

    let mnemonic = Mnemonic::generate(strength)?;
    let phrase = mnemonic.phrase();
    let phrase_str = String::from_utf8(phrase.expose().to_vec())
        .map_err(|e| CliError::InvalidArgs(format!("invalid UTF-8 in mnemonic: {e}")))?;

    println!("{phrase_str}");
    Ok(())
}
