//! Cardano RPC provider abstraction.
//!
//! Cardano needs an RPC provider for three operations: broadcasting a signed
//! transaction, fetching UTxOs for a set of transaction inputs, and fetching an
//! address' token balances. This module defines a provider-agnostic
//! [`CardanoRpcProvider`] trait over those operations and
//! [`resolve_cardano_provider`], which selects the concrete provider from an RPC
//! URL. Provider-specific code lives in the [`koios`] and [`blockfrost`]
//! submodules.
//!
//! The trait is synchronous (all call sites are effectively sync — the balance
//! path bridges via `spawn_blocking`) and object-safe, so the resolver can hand
//! back a `Box<dyn CardanoRpcProvider>`.

mod blockfrost;
mod koios;

pub use blockfrost::BlockfrostProvider;
pub use koios::KoiosProvider;

use crate::TokenBalance;
use std::{collections::BTreeMap, time::Duration};

/// Lovelace-per-ADA exponent (1 ADA = 10^6 lovelace).
const ADA_DECIMALS: u32 = 6;
const REQUESTS_TIMEOUT: Duration = Duration::from_secs(45);

/// Errors returned by a [`CardanoRpcProvider`]. Consumers map these into their
/// own crate-local error types.
#[derive(Debug, thiserror::Error)]
pub enum CardanoRpcError {
    /// Transport-level failure (DNS, TLS, timeout, connection).
    #[error("HTTP error: {0}")]
    Http(String),
    /// The response could not be decoded into the expected shape.
    #[error("decode error: {0}")]
    Decode(String),
    /// The provider returned an error status or a semantically invalid response.
    #[error("RPC error: {0}")]
    Rpc(String),
}

/// Cardano RPC operations, independent of the concrete provider (Koios, Blockfrost, …).
pub trait CardanoRpcProvider: Send + Sync {
    /// Submit a signed transaction (CBOR bytes) and return its hash.
    ///
    /// `expected_tx_id` is the transaction ID the caller computed from the body it
    /// signed; implementations pass the provider's response through
    /// `check_broadcast_tx_id` against it.
    fn broadcast_tx(&self, tx_cbor: &[u8], expected_tx_id: &str)
        -> Result<String, CardanoRpcError>;

    /// Fetch the CBOR-encoded transactions for a set of transaction hashes.
    /// NOTE: The result can be partial if some transactions are not found.
    fn fetch_txs_cbor(
        &self,
        tx_hashes: &[String],
    ) -> Result<BTreeMap<String, String>, CardanoRpcError>;

    /// Fetch the token balances (ADA + native assets) for an address.
    fn get_balances(&self, address: &str) -> Result<Vec<TokenBalance>, CardanoRpcError>;
}

/// Environment variable holding the Blockfrost `project_id` (API key).
pub const BLOCKFROST_PROJECT_ID_ENV: &str = "BLOCKFROST_PROJECT_ID";

const BLOCKFROST_URL_PREFIX: &str = "blockfrost|";
const KOIOS_URL_PREFIX: &str = "koios|";

fn is_blockfrost_url(url: &str) -> bool {
    url.starts_with(BLOCKFROST_URL_PREFIX) || url.contains("blockfrost.io/api")
}

fn is_koios_url(url: &str) -> bool {
    url.starts_with(KOIOS_URL_PREFIX) || url.contains("koios.rest/api")
}

fn strip_provider_prefix(url: &str) -> &str {
    url.strip_prefix(BLOCKFROST_URL_PREFIX)
        .or_else(|| url.strip_prefix(KOIOS_URL_PREFIX))
        .unwrap_or(url)
}

/// Select a Cardano RPC provider from its URL.
///
/// Blockfrost is selected when the URL contains `blockfrost.io/api` or is
/// prefixed with `blockfrost|` (reading the `project_id` from
/// [`BLOCKFROST_PROJECT_ID_ENV`]). Koios is selected when the URL contains
/// `koios.rest/api` or is prefixed with `koios|`. Any other URL is rejected.
pub fn resolve_cardano_provider(url: &str) -> Result<Box<dyn CardanoRpcProvider>, CardanoRpcError> {
    if is_blockfrost_url(url) {
        let project_id = std::env::var(BLOCKFROST_PROJECT_ID_ENV).map_err(|_| {
            CardanoRpcError::Rpc(format!(
                "{BLOCKFROST_PROJECT_ID_ENV} environment variable is required for Blockfrost RPC"
            ))
        })?;
        Ok(Box::new(BlockfrostProvider::new(
            strip_provider_prefix(url),
            project_id,
        )))
    } else if is_koios_url(url) {
        Ok(Box::new(KoiosProvider::new(strip_provider_prefix(url))))
    } else {
        Err(CardanoRpcError::Rpc(format!(
            "unsupported Cardano RPC URL: {url}"
        )))
    }
}

/// Check that a submission response names the transaction that was submitted.
///
/// A provider's response is untrusted: a 64-character body is not necessarily hex,
/// and a well-formed ID can belong to a different transaction. Both would otherwise
/// be reported back as a successful broadcast of the caller's transaction.
///
/// A failure here says nothing about whether the transaction was accepted — the
/// provider may have submitted it before answering — so callers must not resubmit on
/// this error. The expected ID is included so it can be looked up on-chain instead.
fn check_broadcast_tx_id(body: &str, expected_tx_id: &str) -> Result<String, CardanoRpcError> {
    let body = body.trim();
    let invalid = || {
        CardanoRpcError::Rpc(format!(
            "Cardano broadcast: invalid transaction hash in response for {expected_tx_id}: {body}"
        ))
    };

    // Koios and Blockfrost both answer with a JSON string. Bare hex stays accepted for
    // other deployments, but malformed quoting does not.
    let tx_id = if body.starts_with('"') {
        serde_json::from_str::<String>(body).map_err(|_| invalid())?
    } else {
        body.to_string()
    };

    let mut id_bytes = [0u8; 32];
    hex::decode_to_slice(&tx_id, &mut id_bytes).map_err(|_| invalid())?;
    let tx_id = hex::encode(id_bytes);

    if !tx_id.eq_ignore_ascii_case(expected_tx_id) {
        return Err(CardanoRpcError::Rpc(format!(
            "Cardano broadcast: transaction hash mismatch: expected {expected_tx_id}, got {tx_id}"
        )));
    }

    Ok(tx_id)
}

/// Shared blocking HTTP client used by the providers.
fn blocking_client() -> Result<reqwest::blocking::Client, CardanoRpcError> {
    reqwest::blocking::Client::builder()
        .timeout(REQUESTS_TIMEOUT)
        .build()
        .map_err(|e| CardanoRpcError::Http(e.to_string()))
}

/// Largest response body a provider will buffer. These endpoints are untrusted — a
/// hostile or broken one could otherwise stream an unbounded body and exhaust memory
/// before a single byte is validated. Legitimate balance / UTxO / broadcast payloads
/// are orders of magnitude smaller.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Read a blocking response body into memory, refusing to buffer more than
/// [`MAX_RESPONSE_BYTES`]. `.text()` and `.json()` read the whole body first, so
/// reading through a capped reader is what enforces the bound.
fn read_capped_body(resp: reqwest::blocking::Response) -> Result<Vec<u8>, CardanoRpcError> {
    use std::io::Read;
    let mut buf = Vec::new();
    // One byte past the cap, so a body sitting exactly at the limit still reads.
    resp.take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CardanoRpcError::Http(format!("reading response: {e}")))?;

    if buf.len() > MAX_RESPONSE_BYTES {
        return Err(CardanoRpcError::Rpc(format!(
            "response exceeds the {MAX_RESPONSE_BYTES}-byte limit"
        )));
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TX_ID: &str = "6c84b1c9ac839cad80b37ff528e7c6f9991de7d1b9b16055a6d8f7df0a7fa7ee";

    #[test]
    fn broadcast_id_accepts_json_and_bare_hex() {
        for body in [TX_ID.to_string(), format!("\"{TX_ID}\"")] {
            assert_eq!(check_broadcast_tx_id(&body, TX_ID).unwrap(), TX_ID);
        }
    }

    #[test]
    fn broadcast_id_normalizes_whitespace_and_hex_case() {
        for body in [
            format!(" \n{TX_ID}\n"),
            format!(" \n\"{}\"\n", TX_ID.to_uppercase()),
        ] {
            assert_eq!(check_broadcast_tx_id(&body, TX_ID).unwrap(), TX_ID);
        }
    }

    #[test]
    fn broadcast_id_rejects_a_malformed_response() {
        // None of these is 32 bytes of hex, however close to that size it looks:
        // "é" is two bytes wide, so the last body is 64 bytes but 32 characters.
        for body in [
            String::new(),
            "bad".into(),
            "z".repeat(64),
            format!("\"{TX_ID}"),
            format!("[{TX_ID}]"),
            "é".repeat(32),
        ] {
            let err = check_broadcast_tx_id(&body, TX_ID).unwrap_err();
            assert!(
                err.to_string().contains("invalid transaction hash"),
                "{body:?}: {err}"
            );
        }
    }

    #[test]
    fn broadcast_id_rejects_a_different_transaction() {
        let err = check_broadcast_tx_id(&format!("\"{}\"", "00".repeat(32)), TX_ID).unwrap_err();
        assert!(
            err.to_string().contains("transaction hash mismatch"),
            "{err}"
        );
        assert!(
            err.to_string().contains(TX_ID),
            "the error should name the ID to look up on-chain: {err}"
        );
    }

    #[test]
    fn resolve_defaults_to_koios() {
        // Non-blockfrost URL resolves without needing any env var.
        let provider = resolve_cardano_provider("https://api.koios.rest/api/v1").unwrap();
        // Smoke: the boxed provider is usable for the no-op empty utxo case.
        assert_eq!(provider.fetch_txs_cbor(&[]).unwrap(), BTreeMap::new());
    }
}
