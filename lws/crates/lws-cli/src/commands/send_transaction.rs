use lws_core::{ChainType, Config};
use lws_signer::{signer_for_chain, HdDeriver, Mnemonic};
use std::process::Command;
use zeroize::Zeroize;

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

    // 1. Sign the transaction
    let mut mnemonic_str = super::resolve_mnemonic(wallet_name)?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(tx_hex);
    let tx_bytes = hex::decode(tx_hex_clean)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hex transaction: {e}")))?;

    let signer = signer_for_chain(chain.chain_type);
    let path = signer.default_derivation_path(index);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
    let output = signer.sign_transaction(key.expose(), &tx_bytes)?;

    // 2. Resolve RPC URL using exact chain_id
    let rpc_url = resolve_rpc_url(chain.chain_id, chain.chain_type, rpc_url_override)?;

    // 3. Broadcast
    let tx_hash = broadcast(chain.chain_type, &rpc_url, &output.signature)?;

    // 4. Output
    if json_output {
        let obj = serde_json::json!({
            "tx_hash": tx_hash,
            "chain": chain_str,
            "rpc_url": rpc_url,
            "signature": hex::encode(&output.signature),
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", tx_hash);
    }

    // 5. Audit log
    audit::log_broadcast(wallet_name, chain_str, &tx_hash);

    Ok(())
}

/// Resolve the RPC URL: CLI flag > config override (exact chain_id) > config (namespace) > built-in default.
fn resolve_rpc_url(chain_id: &str, chain_type: ChainType, flag: Option<&str>) -> Result<String, CliError> {
    if let Some(url) = flag {
        return Ok(url.to_string());
    }

    let config = Config::load_or_default();
    let defaults = Config::default_rpc();

    // Try exact chain_id match first
    if let Some(url) = config.rpc.get(chain_id) {
        return Ok(url.clone());
    }
    if let Some(url) = defaults.get(chain_id) {
        return Ok(url.clone());
    }

    // Fallback to namespace match
    let namespace = chain_type.namespace();
    for (key, url) in &config.rpc {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }
    for (key, url) in &defaults {
        if key.starts_with(namespace) {
            return Ok(url.clone());
        }
    }

    Err(CliError::InvalidArgs(format!(
        "no RPC URL configured for chain '{}' — use --rpc-url or add to ~/.lws/config.json",
        chain_id
    )))
}

/// Broadcast a signed transaction via curl, dispatching per chain type.
fn broadcast(chain: ChainType, rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    match chain {
        ChainType::Evm => broadcast_evm(rpc_url, signed_bytes),
        ChainType::Solana => broadcast_solana(rpc_url, signed_bytes),
        ChainType::Bitcoin => broadcast_bitcoin(rpc_url, signed_bytes),
        ChainType::Cosmos => broadcast_cosmos(rpc_url, signed_bytes),
        ChainType::Tron => broadcast_tron(rpc_url, signed_bytes),
        ChainType::Ton => broadcast_ton(rpc_url, signed_bytes),
    }
}

fn broadcast_evm(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    let hex_tx = format!("0x{}", hex::encode(signed_bytes));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_sendRawTransaction",
        "params": [hex_tx],
        "id": 1
    });
    let resp = curl_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

fn broadcast_solana(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "sendTransaction",
        "params": [b64_tx],
        "id": 1
    });
    let resp = curl_post_json(rpc_url, &body.to_string())?;
    extract_json_field(&resp, "result")
}

fn broadcast_bitcoin(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!("{}/tx", rpc_url.trim_end_matches('/'));
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X", "POST",
            "-H", "Content-Type: text/plain",
            "-d", &hex_tx,
            &url,
        ])
        .output()
        .map_err(|e| CliError::InvalidArgs(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::InvalidArgs(format!("broadcast failed: {stderr}")));
    }

    let tx_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tx_hash.is_empty() {
        return Err(CliError::InvalidArgs("empty response from broadcast".into()));
    }
    Ok(tx_hash)
}

fn broadcast_cosmos(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    use base64::Engine;
    let b64_tx = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!(
        "{}/cosmos/tx/v1beta1/txs",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "tx_bytes": b64_tx,
        "mode": "BROADCAST_MODE_SYNC"
    });
    let resp = curl_post_json(&url, &body.to_string())?;
    // Response has { "tx_response": { "txhash": "..." } }
    let parsed: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|e| CliError::InvalidArgs(format!("failed to parse response: {e}")))?;
    parsed["tx_response"]["txhash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::InvalidArgs(format!("no txhash in response: {resp}")))
}

fn broadcast_tron(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    let hex_tx = hex::encode(signed_bytes);
    let url = format!(
        "{}/wallet/broadcasthex",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "transaction": hex_tx });
    let resp = curl_post_json(&url, &body.to_string())?;
    extract_json_field(&resp, "txid")
}

fn broadcast_ton(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, CliError> {
    use base64::Engine;
    let b64_boc = base64::engine::general_purpose::STANDARD.encode(signed_bytes);
    let url = format!(
        "{}/sendBoc",
        rpc_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "boc": b64_boc });
    let resp = curl_post_json(&url, &body.to_string())?;
    let parsed: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|e| CliError::InvalidArgs(format!("invalid JSON response: {e}")))?;
    parsed["result"]["hash"]
        .as_str()
        .map(|s: &str| s.to_string())
        .ok_or_else(|| CliError::InvalidArgs(format!("no hash in response: {resp}")))
}

/// POST JSON via curl and return the response body.
fn curl_post_json(url: &str, body: &str) -> Result<String, CliError> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", body,
            url,
        ])
        .output()
        .map_err(|e| CliError::InvalidArgs(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::InvalidArgs(format!("broadcast failed: {stderr}")));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Extract a string field from a JSON-RPC response.
fn extract_json_field(json_str: &str, field: &str) -> Result<String, CliError> {
    let parsed: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| CliError::InvalidArgs(format!("failed to parse response: {e}")))?;

    if let Some(error) = parsed.get("error") {
        return Err(CliError::InvalidArgs(format!("RPC error: {error}")));
    }

    parsed[field]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| CliError::InvalidArgs(format!("no '{field}' in response: {json_str}")))
}
