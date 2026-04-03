use ows_signer::signer_for_chain;

use crate::{parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_data: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;

    if chain.chain_type == ows_core::ChainType::Bitcoin {
        if let Some(result) = try_sign_psbt(wallet_name, tx_data, index)? {
            return print_result(&result.signature, result.recovery_id, json_output);
        }
    }

    sign_regular_transaction(&chain, wallet_name, tx_data, index, json_output)
}

fn try_sign_psbt(
    wallet_name: &str,
    tx_data: &str,
    index: u32,
) -> Result<Option<ows_lib::types::SignResult>, CliError> {
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        return Ok(None);
    }

    let key = match super::resolve_signing_key(wallet_name, ows_core::ChainType::Bitcoin, index) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };

    let signer = signer_for_chain(ows_core::ChainType::Bitcoin);

    match signer.sign_psbt(key.expose(), tx_data.as_bytes()) {
        Ok(signed_psbt) => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&signed_psbt);
            Ok(Some(ows_lib::types::SignResult {
                signature: b64,
                recovery_id: None,
            }))
        }
        Err(_) => Ok(None),
    }
}

fn sign_regular_transaction(
    chain: &ows_core::Chain,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::peek_passphrase();
    if passphrase
        .as_deref()
        .is_some_and(|p| p.starts_with(ows_lib::key_store::TOKEN_PREFIX))
    {
        let result = ows_lib::sign_transaction(
            wallet_name,
            &chain.chain_id,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            None,
        )?;
        return print_result(&result.signature, result.recovery_id, json_output);
    }

    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex: {e}")))?;

    let signer = signer_for_chain(chain.chain_type);
    let signable = signer.extract_signable_bytes(&tx_bytes)?;
    let output = signer.sign_transaction(key.expose(), signable)?;

    print_result(
        &hex::encode(&output.signature),
        output.recovery_id,
        json_output,
    )
}

fn print_result(
    signature: &str,
    recovery_id: Option<u8>,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": signature,
            "recovery_id": recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{signature}");
    }
    Ok(())
}
