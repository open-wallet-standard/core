//! Nano RPC helpers (account_info, work_generate, process).
//!
//! Uses `curl` for HTTP, consistent with the rest of ows-lib (no added HTTP deps).

use crate::error::OwsLibError;
use std::process::Command;

/// Call a Nano RPC action via curl and return the parsed JSON response.
fn nano_rpc_call(
    rpc_url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, OwsLibError> {
    let body_str = body.to_string();
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            &body_str,
            rpc_url,
        ])
        .output()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OwsLibError::BroadcastFailed(format!(
            "Nano RPC call failed: {stderr}"
        )));
    }

    let resp_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)?;

    // Check for Nano RPC error field
    if let Some(error) = parsed.get("error") {
        let msg = error.as_str().unwrap_or("unknown error");
        return Err(OwsLibError::BroadcastFailed(format!(
            "Nano RPC error: {msg}"
        )));
    }

    Ok(parsed)
}

/// Account info from the Nano network.
#[derive(Debug, Clone)]
pub struct NanoAccountInfo {
    /// Current frontier (head block hash), hex-encoded.
    pub frontier: String,
    /// Current balance in raw (decimal string).
    pub balance: String,
    /// Representative nano_ address.
    pub representative: String,
}

/// Query `account_info` for a Nano account.
///
/// Returns `None` if the account is not yet opened (no blocks published).
pub fn account_info(rpc_url: &str, account: &str) -> Result<Option<NanoAccountInfo>, OwsLibError> {
    let body = serde_json::json!({
        "action": "account_info",
        "account": account,
        "representative": "true"
    });

    match nano_rpc_call(rpc_url, &body) {
        Ok(resp) => {
            let frontier = resp["frontier"]
                .as_str()
                .ok_or_else(|| {
                    OwsLibError::BroadcastFailed("no frontier in account_info response".into())
                })?
                .to_string();
            let balance = resp["balance"]
                .as_str()
                .ok_or_else(|| {
                    OwsLibError::BroadcastFailed("no balance in account_info response".into())
                })?
                .to_string();
            let representative = resp["representative"]
                .as_str()
                .ok_or_else(|| {
                    OwsLibError::BroadcastFailed(
                        "no representative in account_info response".into(),
                    )
                })?
                .to_string();

            Ok(Some(NanoAccountInfo {
                frontier,
                balance,
                representative,
            }))
        }
        Err(OwsLibError::BroadcastFailed(msg)) if msg.contains("Account not found") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Request proof-of-work from a single RPC endpoint.
fn work_generate_single(
    rpc_url: &str,
    hash: &str,
    difficulty: &str,
) -> Result<String, OwsLibError> {
    let body = serde_json::json!({
        "action": "work_generate",
        "hash": hash,
        "difficulty": difficulty
    });

    let resp = nano_rpc_call(rpc_url, &body)?;

    resp["work"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OwsLibError::BroadcastFailed("no work in work_generate response".into()))
}

/// Default PoW fallback endpoint, tried when the primary RPC fails work_generate.
const FALLBACK_WORK_URL: &str = "https://rpc.nano.to";

/// Request proof-of-work with multi-endpoint fallback.
///
/// Tries endpoints in order:
/// 1. The primary `rpc_url`
/// 2. URLs from `NANO_WORK_URL` env var (semicolon-separated URLs)
/// 3. Built-in fallback endpoint
///
/// All remote errors are collected and logged to stderr. If every remote fails
/// and `NANO_CPU_POW=1` is set, a future CPU fallback would go here.
pub fn work_generate(rpc_url: &str, hash: &str, difficulty: &str) -> Result<String, OwsLibError> {
    let mut endpoints: Vec<String> = vec![rpc_url.to_string()];

    if let Ok(urls) = std::env::var("NANO_WORK_URL") {
        for url in urls.split(';') {
            let url = url.trim();
            if !url.is_empty() && url != rpc_url {
                endpoints.push(url.to_string());
            }
        }
    }

    if !endpoints.iter().any(|e| e == FALLBACK_WORK_URL) {
        endpoints.push(FALLBACK_WORK_URL.to_string());
    }

    let mut last_error = None;

    for endpoint in &endpoints {
        match work_generate_single(endpoint, hash, difficulty) {
            Ok(work) => return Ok(work),
            Err(e) => {
                eprintln!("  PoW failed on {endpoint}: {e}");
                last_error = Some(e);
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| OwsLibError::BroadcastFailed("no PoW endpoints available".into())))
}

/// Publish a block to the Nano network via `process` RPC.
///
/// Returns the block hash on success.
pub fn process_block(
    rpc_url: &str,
    block_json: &serde_json::Value,
    subtype: &str,
) -> Result<String, OwsLibError> {
    let body = serde_json::json!({
        "action": "process",
        "json_block": "true",
        "subtype": subtype,
        "block": block_json
    });

    let resp = nano_rpc_call(rpc_url, &body)?;

    resp["hash"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| OwsLibError::BroadcastFailed(format!("no hash in process response: {resp}")))
}

/// PoW difficulty thresholds (as hex strings for work_generate RPC).
pub const SEND_DIFFICULTY: &str = "fffffff800000000";
pub const RECEIVE_DIFFICULTY: &str = "fffffe0000000000";
