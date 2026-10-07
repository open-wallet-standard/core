use ows_signer::signer_for_chain;

use crate::{audit, parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    // Check for API token in passphrase — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    let actor = audit::Actor::from_passphrase(passphrase.as_deref());
    if matches!(actor, audit::Actor::ApiKey) {
        let result = ows_lib::sign_transaction(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            None,
        );
        let result = match result {
            Ok(result) => result,
            // A policy refusal is a verdict worth recording — an agent repeatedly hitting its cap is
            // exactly what the trail should show — so it is logged before the error propagates.
            Err(e) => {
                if let Some(outcome) = audit::denial(&e) {
                    log_signed(wallet_name, chain_str, &actor, &outcome);
                }
                return Err(e.into());
            }
        };
        log_signed(wallet_name, chain_str, &actor, &audit::Outcome::Allowed);
        return print_result(
            &result.signature,
            result.recovery_id,
            result.transaction,
            json_output,
        );
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_bytes = ows_lib::decode_tx_input(&chain, tx_hex)?;
    // Owner mode: full authority, no policy gate.
    let signable_tx = ows_lib::prepare_signable_tx(&chain, tx_bytes, &key, |_| Ok(()))?;

    let signer = signer_for_chain(&chain)?;
    let signable = signer.extract_signable_bytes(&signable_tx)?;
    let output = signer.sign_transaction(key.expose(), signable)?;
    let transaction =
        ows_lib::signed_transaction_hex(&chain, signer.as_ref(), &signable_tx, &output)?;

    log_signed(wallet_name, chain_str, &actor, &audit::Outcome::Allowed);

    print_result(
        &hex::encode(&output.signature),
        output.recovery_id,
        transaction,
        json_output,
    )
}

/// Trace the signature this command just handed out. `sign tx` broadcasts nothing, so without this
/// the artifact — on Midnight a fully sealed, submittable transaction — would leave the wallet with
/// no record that it ever existed. Resolving the wallet's id keeps the record joinable with the rest
/// of the log, which keys on ids rather than renameable names; a wallet that no longer resolves is
/// left untraced rather than failing the command it already completed.
fn log_signed(wallet_name: &str, chain_str: &str, actor: &audit::Actor, outcome: &audit::Outcome) {
    if let Ok(info) = ows_lib::get_wallet(wallet_name, None) {
        audit::log_transaction_signed(&info.id, chain_str, actor, outcome);
    }
}

fn print_result(
    signature: &str,
    recovery_id: Option<u8>,
    transaction: Option<String>,
    json_output: bool,
) -> Result<(), CliError> {
    if json_output {
        let mut obj = serde_json::json!({
            "signature": signature,
            "recovery_id": recovery_id,
        });
        // Only chains that seal a complete transaction at sign time (Midnight) carry this.
        if let Some(transaction) = transaction {
            obj["transaction"] = serde_json::Value::String(transaction);
        }
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{signature}");
    }
    Ok(())
}
