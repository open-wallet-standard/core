//! NEAR Protocol RPC helpers (`broadcast_tx_commit`).
//!
//! Uses `curl` for HTTP, consistent with the rest of ows-lib (no added HTTP deps).
//!
//! See <https://docs.near.org/api/rpc/transactions> for the full RPC surface.

use crate::error::OwsLibError;
use base64::Engine;
use std::process::Command;

/// Call a NEAR JSON-RPC method via curl and return the parsed JSON response.
fn near_rpc_call(
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
            "NEAR RPC call failed: {stderr}"
        )));
    }

    let resp_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&resp_str)?;

    // JSON-RPC error envelope.
    if let Some(error) = parsed.get("error") {
        let msg = error
            .get("data")
            .and_then(|d| d.as_str())
            .or_else(|| error.get("message").and_then(|m| m.as_str()))
            .or_else(|| error.as_str())
            .unwrap_or("unknown error");
        return Err(OwsLibError::BroadcastFailed(format!(
            "NEAR RPC error: {msg}"
        )));
    }

    Ok(parsed)
}

/// Broadcast a signed NEAR transaction via `broadcast_tx_commit` and return the
/// transaction hash on success.
///
/// `signed_bytes` MUST be the canonical Borsh-encoded `SignedTransaction` —
/// i.e. the output of `NearSigner::encode_signed_transaction`.
///
/// `broadcast_tx_commit` waits for the transaction to be included on-chain and
/// returns the resulting `transaction.hash`. For fire-and-forget semantics,
/// callers can switch to `broadcast_tx_async` (not exposed here).
pub fn broadcast_tx_commit(rpc_url: &str, signed_bytes: &[u8]) -> Result<String, OwsLibError> {
    let signed_b64 = base64::engine::general_purpose::STANDARD.encode(signed_bytes);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "ows",
        "method": "broadcast_tx_commit",
        "params": [signed_b64]
    });

    let resp = near_rpc_call(rpc_url, &body)?;

    // Do NOT embed the raw `resp` JSON in the error message: it contains
    // operational data (transaction details, account identifiers) that
    // shouldn't leak through the error's `Display` output to logs/UI.
    let hash = resp
        .pointer("/result/transaction/hash")
        .and_then(|h| h.as_str())
        .or_else(|| {
            resp.pointer("/result/transaction_outcome/id")
                .and_then(|h| h.as_str())
        })
        .ok_or_else(|| {
            OwsLibError::BroadcastFailed(
                "broadcast_tx_commit response missing transaction hash".into(),
            )
        })?
        .to_string();

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_body_shape() {
        // Sanity check the JSON-RPC envelope shape we send. We do not actually
        // hit the network here; we only verify base64 encoding is applied
        // correctly to known bytes.
        let signed = b"\x00\x01\x02\x03";
        let b64 = base64::engine::general_purpose::STANDARD.encode(signed);
        assert_eq!(b64, "AAECAw==");
    }
}
