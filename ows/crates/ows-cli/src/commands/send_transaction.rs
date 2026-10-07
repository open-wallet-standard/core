use crate::{audit, parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
    rpc_url_override: Option<&str>,
) -> Result<(), CliError> {
    // Check for API token — route through library for policy enforcement
    let passphrase = super::peek_passphrase();
    let actor = audit::Actor::from_passphrase(passphrase.as_deref());
    if matches!(actor, audit::Actor::ApiKey) {
        let result = ows_lib::sign_and_send(
            wallet_name,
            chain_str,
            tx_hex,
            passphrase.as_deref(),
            Some(index),
            rpc_url_override,
            None,
        );
        let result = match result {
            Ok(result) => result,
            // A policy refusal blocks the signing, so nothing is broadcast — record the verdict under
            // the operation that was actually gated.
            Err(e) => {
                if let Some(outcome) = audit::denial(&e) {
                    log_signed(wallet_name, chain_str, &actor, &outcome);
                }
                return Err(e.into());
            }
        };
        log_signed(wallet_name, chain_str, &actor, &audit::Outcome::Allowed);

        if json_output {
            let obj = serde_json::json!({
                "tx_hash": result.tx_hash,
                "chain": chain_str,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        } else {
            println!("{}", result.tx_hash);
        }

        log_broadcast(wallet_name, chain_str, &result.tx_hash);
        return Ok(());
    }

    // Owner mode: resolve key directly (existing behavior)
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_bytes = ows_lib::decode_tx_input(&chain, tx_hex)?;
    // Owner mode: full authority, no policy gate.
    let signable_tx = ows_lib::prepare_signable_tx(&chain, tx_bytes, &key, |_| Ok(()))?;

    let result = ows_lib::sign_encode_and_broadcast(
        key.expose(),
        chain_str,
        &signable_tx,
        rpc_url_override,
    )?;

    log_signed(wallet_name, chain_str, &actor, &audit::Outcome::Allowed);

    if json_output {
        let obj = serde_json::json!({
            "tx_hash": result.tx_hash,
            "chain": chain_str,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.tx_hash);
    }

    log_broadcast(wallet_name, chain_str, &result.tx_hash);

    Ok(())
}

/// Trace the broadcast, keyed on the wallet's **id**. The rest of the log keys on ids, so recording
/// the name here — which a later `wallet rename` invalidates — left broadcasts unjoinable with the
/// wallet's own records. A wallet that no longer resolves is left untraced rather than failing a
/// transaction that is already on-chain.
fn log_broadcast(wallet_name: &str, chain_str: &str, tx_hash: &str) {
    if let Ok(info) = ows_lib::get_wallet(wallet_name, None) {
        audit::log_broadcast(&info.id, chain_str, tx_hash);
    }
}

/// `send-tx` signs *and* broadcasts, so it writes both records: signing is what a policy gates, and a
/// refusal here means nothing was ever broadcast. Recording only the broadcast would leave every
/// denied attempt — and the signing half of every successful one — invisible.
fn log_signed(wallet_name: &str, chain_str: &str, actor: &audit::Actor, outcome: &audit::Outcome) {
    if let Ok(info) = ows_lib::get_wallet(wallet_name, None) {
        audit::log_transaction_signed(&info.id, chain_str, actor, outcome);
    }
}
