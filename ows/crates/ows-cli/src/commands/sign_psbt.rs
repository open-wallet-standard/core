use crate::CliError;

pub fn run(
    wallet_name: &str,
    psbt_base64: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        return Err(CliError::InvalidArgs(
            "Bitcoin PSBT signing via API key is not yet supported".into(),
        ));
    }

    let result = ows_lib::sign_psbt(
        wallet_name,
        psbt_base64,
        passphrase.as_deref(),
        Some(index),
        None,
    )?;

    if json_output {
        let obj = serde_json::json!({
            "psbt": result.psbt,
            "signed_inputs": result.signed_inputs,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.psbt);
    }

    Ok(())
}
