use crate::CliError;

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let output = ows_lib::sign_transaction(wallet_name, chain_str, tx_hex, Some(index), None)?;

    if json_output {
        let obj = serde_json::json!({
            "signature": output.signature,
            "recovery_id": output.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", output.signature);
    }

    Ok(())
}
