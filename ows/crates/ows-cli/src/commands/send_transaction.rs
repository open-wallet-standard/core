use crate::{audit, parse_chain, CliError};

pub fn run(
    chain_str: &str,
    wallet_name: &str,
    tx_hex: &str,
    index: u32,
    json_output: bool,
    rpc_url_override: Option<&str>,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let key = super::resolve_signing_key(wallet_name, chain.chain_type, index)?;

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex transaction: {e}")))?;

    // Delegate sign → encode → broadcast to the library so this pipeline
    // is never duplicated between the CLI and the library.
    let result =
        ows_lib::sign_encode_and_broadcast(key.expose(), chain_str, &tx_bytes, rpc_url_override)?;

    if json_output {
        let obj = serde_json::json!({
            "tx_hash": result.tx_hash,
            "chain": chain_str,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.tx_hash);
    }

    audit::log_broadcast(wallet_name, chain_str, &result.tx_hash);

    Ok(())
}
