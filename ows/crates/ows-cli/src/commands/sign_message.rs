use ows_signer::chains::EvmSigner;
use ows_signer::signer_for_chain;
use ows_signer::ChainSigner;

use crate::{audit, parse_chain, CliError};

#[allow(clippy::too_many_arguments)]
pub fn run(
    chain_str: &str,
    wallet_name: &str,
    message: &str,
    encoding: &str,
    typed_data: Option<&str>,
    index: u32,
    json_output: bool,
    address: Option<&str>,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    let actor = audit::Actor::from_passphrase(passphrase.as_deref());
    let kind = if typed_data.is_some() {
        "typed_data"
    } else {
        "message"
    };
    if matches!(actor, audit::Actor::ApiKey) {
        let result = if let Some(td_json) = typed_data {
            ows_lib::sign_typed_data(
                wallet_name,
                chain_str,
                td_json,
                passphrase.as_deref(),
                Some(index),
                address,
                None,
            )
        } else {
            ows_lib::sign_message(
                wallet_name,
                chain_str,
                message,
                passphrase.as_deref(),
                Some(encoding),
                Some(index),
                address,
                None,
            )
        };
        let result = match result {
            Ok(result) => result,
            // A policy refusal is a verdict worth recording, so it is logged before propagating.
            Err(e) => {
                if let Some(outcome) = audit::denial(&e) {
                    log_signed(wallet_name, chain_str, kind, &actor, &outcome);
                }
                return Err(e.into());
            }
        };
        log_signed(
            wallet_name,
            chain_str,
            kind,
            &actor,
            &audit::Outcome::Allowed,
        );
        return print_result(&result, json_output);
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let signer = signer_for_chain(&chain)?;

    let output = if let Some(td_json) = typed_data {
        if chain.chain_type != ows_core::ChainType::Evm {
            return Err(CliError::InvalidArgs(
                "--typed-data is only supported for EVM chains".into(),
            ));
        }
        ChainSigner::verify_sign_message_address(&*signer, key.expose(), address)?;
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
        signer.sign_message(key.expose(), &msg_bytes, address)?
    };

    // Encode per chain — Midnight prefixes the x-only pubkey to the BIP-340 signature; every other
    // chain returns the hex signature as-is.
    let result = ows_lib::sign_result_from_message_output(chain.chain_type, &output)?;
    log_signed(
        wallet_name,
        chain_str,
        kind,
        &actor,
        &audit::Outcome::Allowed,
    );
    print_result(&result, json_output)
}

/// Trace the signature this command just handed out — a message signature is a bearer artifact too,
/// and an EVM typed-data one can authorize value movement. Same wallet-id resolution as `sign tx`:
/// keyed on the id so the record joins the rest of the log, and skipped rather than fatal when the
/// wallet no longer resolves.
fn log_signed(
    wallet_name: &str,
    chain_str: &str,
    kind: &str,
    actor: &audit::Actor,
    outcome: &audit::Outcome,
) {
    if let Ok(info) = ows_lib::get_wallet(wallet_name, None) {
        audit::log_message_signed(&info.id, chain_str, kind, actor, outcome);
    }
}

fn print_result(result: &ows_lib::SignResult, json_output: bool) -> Result<(), CliError> {
    if json_output {
        let obj = serde_json::json!({
            "signature": result.signature,
            "recovery_id": result.recovery_id,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.signature);
    }
    Ok(())
}
