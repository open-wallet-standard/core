use ows_signer::chains::EvmSigner;
use ows_signer::signer_for_chain;

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
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let signer = signer_for_chain(chain.chain_type);

    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != ows_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        EvmSigner.sign_typed_data(key.expose(), td_json)?
    } else {
        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(message)
                .map_err(|e| CliError::InvalidArgs(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(CliError::InvalidArgs(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )))
            }
        };
        signer.sign_message(key.expose(), &msg_bytes)?
    };

    if json_output {
        let obj = serde_json::json!({
            "signature": hex::encode(&output.signature),
            "recovery_id": output.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", hex::encode(&output.signature));
    }

    Ok(())
}
