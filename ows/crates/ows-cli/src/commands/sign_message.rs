use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    message: &str,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != ows_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        ows_lib::sign_typed_data(wallet_name, chain_str, td_json, Some(index), None)?
    } else {
        ows_lib::sign_message(wallet_name, chain_str, message, Some(encoding), Some(index), None)?
    };

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
