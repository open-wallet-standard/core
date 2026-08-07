//! Submit a finalized Midnight ledger transaction (`midnight:transaction…` bytes) to a Midnight
//! node via `author_submitExtrinsic` (`Midnight::send_mn_transaction`).
//!
//! If `submit` fails, we also try `system_dryRun` and `payment_queryInfo` so the caller gets the
//! underlying runtime error rather than a bare submission error.

use std::time::Duration;

use super::urls::{http_url_to_ws_url, is_loopback, without_credentials};

fn err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Bounds on each node RPC step, so an unresponsive node fails the command instead of hanging it.
const NODE_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// How much of an unparsable node response an error quotes.
const ERROR_BODY_MAX_CHARS: usize = 200;

/// Node ledger code for per-segment overspend (`InvalidTransaction::Custom(138)`).
const LEDGER_BALANCE_CHECK_OVERSPEND: u16 = 138;
/// Input references a UTXO absent from ledger state (`InvalidTransaction::Custom(195)`).
const LEDGER_INPUT_NOT_IN_UTXOS: u16 = 195;

type SealedTx = midnight_ledger::structure::Transaction<
    midnight_base_crypto::signatures::Signature,
    midnight_ledger::structure::ProofMarker,
    <midnight_ledger::structure::ProofMarker as midnight_ledger::structure::ProofKind<
        midnight_storage::db::InMemoryDB,
    >>::Pedersen,
    midnight_storage::db::InMemoryDB,
>;

/// True when the tx looks like a single-party swap offer (inputs on one side, outputs on
/// another) rather than a self-contained contract call.
fn is_swap_shaped_offer(
    stx: &midnight_ledger::structure::StandardTransaction<
        midnight_base_crypto::signatures::Signature,
        midnight_ledger::structure::ProofMarker,
        <midnight_ledger::structure::ProofMarker as midnight_ledger::structure::ProofKind<
            midnight_storage::db::InMemoryDB,
        >>::Pedersen,
        midnight_storage::db::InMemoryDB,
    >,
) -> bool {
    use std::ops::Deref as _;

    let zswap_output_only = |inputs: usize, outputs: usize| inputs == 0 && outputs > 0;

    for pair_sp in stx.intents.iter() {
        let (_, intent_sp) = pair_sp.deref();
        let intent = intent_sp.deref();
        if let Some(offer) = intent.guaranteed_unshielded_offer.as_ref() {
            let offer = offer.deref();
            if !offer.inputs.is_empty() && offer.outputs.is_empty() {
                return true;
            }
        }
    }

    if let Some(offer) = stx.guaranteed_coins.as_ref() {
        let offer = offer.deref();
        if zswap_output_only(
            offer.inputs.iter_deref().count(),
            offer.outputs.iter_deref().count(),
        ) {
            return true;
        }
    }
    for offer in stx.fallible_coins.values() {
        if zswap_output_only(
            offer.inputs.iter_deref().count(),
            offer.outputs.iter_deref().count(),
        ) {
            return true;
        }
    }

    false
}

/// Detect sealed txs that the ledger will reject on submit (error 138), using the ledger's own
/// per-segment balance aggregation rather than an inputs-vs-outputs heuristic.
fn preflight_sealed_tx_submit(tx: &SealedTx) -> Result<(), std::io::Error> {
    use midnight_ledger::structure::Transaction;

    let Transaction::Standard(stx) = tx else {
        return Ok(());
    };

    let balances = tx
        .balance(None)
        .map_err(|e| err(format!("transaction balance check failed: {e:?}")))?;

    let overspends: Vec<String> = balances
        .into_iter()
        .filter(|(_, bal)| *bal < 0)
        .map(|((_, segment), bal)| format!("segment {segment} overspent by {}", bal.unsigned_abs()))
        .collect();

    if overspends.is_empty() {
        return Ok(());
    }

    let swap_hint = if is_swap_shaped_offer(stx) {
        " Signing/proving succeeded, but this is not submittable alone: share the sealed hex \
         with a counterparty for balanceSealedTransaction, or use a balanced makeIntent / \
         makeTransfer."
    } else {
        ""
    };

    Err(err(format!(
        "transaction is imbalanced ({}) and will be rejected by the node with ledger error \
         {LEDGER_BALANCE_CHECK_OVERSPEND} (BalanceCheckOverspend).{swap_hint}",
        overspends.join("; ")
    )))
}

fn append_balance_overspend_hint(msg: &mut String) {
    if msg.contains("Custom error: 138")
        || msg.contains(&format!("Custom({LEDGER_BALANCE_CHECK_OVERSPEND})"))
        || msg.contains("BalanceCheckOverspend")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_BALANCE_CHECK_OVERSPEND} (BalanceCheckOverspend): the tx is \
             cryptographically valid but not ledger-balanced. Swap-style makeIntent offers must be \
             completed via balanceSealedTransaction before submit."
        ));
    }
}

fn append_input_not_in_utxos_hint(msg: &mut String) {
    if msg.contains(&format!("Custom error: {LEDGER_INPUT_NOT_IN_UTXOS}"))
        || msg.contains(&format!("Custom({LEDGER_INPUT_NOT_IN_UTXOS})"))
        || msg.contains("InputNotInUtxos")
    {
        msg.push_str(&format!(
            "\n\nLedger error {LEDGER_INPUT_NOT_IN_UTXOS} (InputNotInUtxos): a transaction input \
             references a coin that is no longer in the UTXO set (already spent or never existed). \
             This often happens when balancing reuses a cached UTXO snapshot from before a recent \
             submit — retry after `ows fund balance` or wait for wallet sync to catch up."
        ));
    }
}

/// Compute the **ledger** transaction hash (`0x` + 32-byte hex) for a `midnight:transaction…` blob.
fn midnight_ledger_tx_hash_hex(midnight_tx: &[u8]) -> Result<String, std::io::Error> {
    use midnight_base_crypto::signatures::Signature as MnSig;
    use midnight_ledger::structure::{ProofKind, ProofMarker, ProofPreimageMarker, Transaction};
    use midnight_serialize::tagged_deserialize;
    use midnight_storage::db::InMemoryDB;

    type TxMarker = Transaction<
        MnSig,
        ProofMarker,
        <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;
    type TxPreimage = Transaction<
        MnSig,
        ProofPreimageMarker,
        <ProofPreimageMarker as ProofKind<InMemoryDB>>::Pedersen,
        InMemoryDB,
    >;

    let mut reader: &[u8] = midnight_tx;
    if let Ok(tx) = tagged_deserialize::<TxMarker>(&mut reader) {
        let h = tx.transaction_hash();
        return Ok(format!("0x{}", hex::encode(h.0 .0)));
    }
    let mut reader: &[u8] = midnight_tx;
    let tx: TxPreimage = tagged_deserialize::<TxPreimage>(&mut reader)
        .map_err(|e| err(format!("invalid midnight ledger transaction: {e}")))?;
    let h = tx.transaction_hash();
    Ok(format!("0x{}", hex::encode(h.0 .0)))
}

/// `url` for an error message: hosted nodes take their API key in the URL.
fn redacted(url: &str) -> String {
    without_credentials(url.trim()).unwrap_or_else(|| "(unparsable URL)".to_string())
}

fn invalid_scheme(node_rpc_url: &str) -> std::io::Error {
    err(format!(
        "invalid Midnight node RPC URL scheme: {}",
        redacted(node_rpc_url)
    ))
}

/// Refuse a plaintext (`http://` / `ws://`) node URL unless it points at this machine: the
/// connection carries the signed transaction and, for a hosted node, the API key in the URL.
fn require_tls_unless_loopback(node_rpc_url: &str) -> Result<(), std::io::Error> {
    let url = reqwest::Url::parse(node_rpc_url.trim()).map_err(|_| invalid_scheme(node_rpc_url))?;
    match url.scheme() {
        "https" | "wss" => return Ok(()),
        "http" | "ws" => {}
        _ => return Err(invalid_scheme(node_rpc_url)),
    }
    if is_loopback(&url) {
        Ok(())
    } else {
        Err(err(format!(
            "refusing the plaintext Midnight node RPC URL {}: use https:// or wss://, or a \
             loopback address for a local node",
            redacted(node_rpc_url)
        )))
    }
}

fn truncated(text: &str) -> String {
    match text.char_indices().nth(ERROR_BODY_MAX_CHARS) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_string(),
    }
}

fn node_ws_url(node_rpc_url: &str) -> Result<String, std::io::Error> {
    let trimmed = node_rpc_url.trim_end_matches('/');
    if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        return Ok(trimmed.to_string());
    }
    http_url_to_ws_url(trimmed).ok_or_else(|| invalid_scheme(node_rpc_url))
}

fn node_http_url(node_rpc_url: &str) -> Result<String, std::io::Error> {
    let trimmed = node_rpc_url.trim();
    let trimmed = trimmed.trim_end_matches('/');

    fn strip_ws_path_suffix(url: &str) -> String {
        // Many node deployments expose WebSocket at `/ws` while HTTP JSON-RPC is at `/`.
        // If a user pastes the WS URL (e.g. `wss://host/ws`), we want `https://host` for dry-run.
        url.strip_suffix("/ws")
            .or_else(|| url.strip_suffix("/ws/"))
            .unwrap_or(url)
            .to_string()
    }

    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        return Ok(strip_ws_path_suffix(trimmed));
    }
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return Ok(strip_ws_path_suffix(&format!("https://{rest}")));
    }
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return Ok(strip_ws_path_suffix(&format!("http://{rest}")));
    }
    Err(invalid_scheme(node_rpc_url))
}

fn node_ws_client_builder() -> jsonrpsee::ws_client::WsClientBuilder {
    jsonrpsee::ws_client::WsClientBuilder::default()
        .connection_timeout(NODE_CONNECT_TIMEOUT)
        .request_timeout(NODE_REQUEST_TIMEOUT)
}

async fn dry_run_extrinsic(
    node_rpc_url: &str,
    ext_hex: &str,
) -> Result<serde_json::Value, std::io::Error> {
    // Try HTTP first (some providers restrict this; we'll fall back to WS JSON-RPC).
    let http_attempt = async {
        let url = node_http_url(node_rpc_url)?;
        let client = reqwest::Client::builder()
            .connect_timeout(NODE_CONNECT_TIMEOUT)
            .timeout(NODE_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| err(format!("system_dryRun client: {}", e.without_url())))?;
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "system_dryRun",
            "params": [ext_hex],
        });
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| err(format!("system_dryRun request failed: {}", e.without_url())))?;
        let text = resp.text().await.unwrap_or_default();
        serde_json::from_str(&text).map_err(|e| {
            err(format!(
                "system_dryRun response not json: {e} (body={})",
                truncated(&text)
            ))
        })
    }
    .await;

    if http_attempt.is_ok() {
        return http_attempt;
    }

    // Fall back to WS JSON-RPC to avoid HTTP 403s / HTML frontends.
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::rpc_params;

    let ws = node_ws_url(node_rpc_url)?;
    let client = node_ws_client_builder()
        .build(&ws)
        .await
        .map_err(|e| err(format!("system_dryRun ws connect failed: {e}")))?;

    let val: serde_json::Value = client
        .request("system_dryRun", rpc_params![ext_hex])
        .await
        .map_err(|e| err(format!("system_dryRun ws request failed: {e}")))?;

    Ok(val)
}

async fn payment_query_info(
    node_rpc_url: &str,
    ext_hex: &str,
) -> Result<serde_json::Value, std::io::Error> {
    use jsonrpsee::core::client::ClientT as _;
    use jsonrpsee::rpc_params;

    let ws = node_ws_url(node_rpc_url)?;
    let client = node_ws_client_builder()
        .build(&ws)
        .await
        .map_err(|e| err(format!("payment_queryInfo ws connect failed: {e}")))?;

    // `payment_queryInfo(extrinsic_hex, at_hash?)`; null `at` queries at the latest block.
    let val: serde_json::Value = client
        .request(
            "payment_queryInfo",
            rpc_params![ext_hex, serde_json::Value::Null],
        )
        .await
        .map_err(|e| err(format!("payment_queryInfo ws request failed: {e}")))?;
    Ok(val)
}

/// Submit a finalized Midnight ledger transaction (`midnight:transaction…` bytes) to a node.
///
/// `node_rpc_url` is a standard Midnight node JSON-RPC endpoint (e.g.
/// `https://rpc.preview.midnight.network/`); a plaintext one must be a loopback address. The
/// extrinsic is `Midnight::send_mn_transaction` wrapping the raw ledger bytes. On success returns
/// the **ledger** transaction hash (`0x` + hex); a failed or timed-out submit names that hash, since
/// the node may still have accepted the transaction.
pub async fn submit_unshielded_tx(
    node_rpc_url: &str,
    midnight_tx: &[u8],
) -> Result<String, std::io::Error> {
    use subxt::dynamic::Value;
    use subxt::{OnlineClient, PolkadotConfig};

    require_tls_unless_loopback(node_rpc_url)?;
    let ledger_hex = midnight_ledger_tx_hash_hex(midnight_tx)?;

    // Best-effort local check before hitting the node (helps when broadcasting sealed swap offers).
    {
        use midnight_base_crypto::signatures::Signature as MnSig;
        use midnight_ledger::structure::{ProofKind, ProofMarker, Transaction};
        use midnight_serialize::tagged_deserialize;
        use midnight_storage::db::InMemoryDB;

        type TxMarker = Transaction<
            MnSig,
            ProofMarker,
            <ProofMarker as ProofKind<InMemoryDB>>::Pedersen,
            InMemoryDB,
        >;
        let mut reader: &[u8] = midnight_tx;
        if let Ok(tx) = tagged_deserialize::<TxMarker>(&mut reader) {
            preflight_sealed_tx_submit(&tx)?;
        }
    }

    let node_ws_url = node_ws_url(node_rpc_url)?;

    let api = tokio::time::timeout(
        NODE_CONNECT_TIMEOUT,
        OnlineClient::<PolkadotConfig>::from_url(&node_ws_url),
    )
    .await
    .map_err(|_| {
        err(format!(
            "timed out connecting to the Midnight node RPC after {}s",
            NODE_CONNECT_TIMEOUT.as_secs()
        ))
    })?
    .map_err(|e| err(format!("failed to connect to Midnight node RPC: {e}")))?;

    let call = subxt::dynamic::tx(
        "Midnight",
        "send_mn_transaction",
        vec![Value::from_bytes(midnight_tx)],
    );

    let tx_client = api.tx();

    let ext = tx_client.create_unsigned(&call).map_err(|e| {
        err(format!(
            "failed to build unsigned extrinsic (check node metadata / pallet name): {e}"
        ))
    })?;

    // Precompute encoded extrinsic hex for diagnostics / dry-run.
    let ext_hex = format!("0x{}", hex::encode(ext.encoded()));

    let submitted = tokio::time::timeout(NODE_REQUEST_TIMEOUT, ext.submit())
        .await
        .map_err(|_| {
            err(format!(
                "submit of transaction {ledger_hex} timed out after {}s; the node may still have \
                 accepted it, so check whether it landed before retrying",
                NODE_REQUEST_TIMEOUT.as_secs()
            ))
        })?;
    if let Err(e) = submitted {
        // Attempt to extract a more helpful runtime error via `system_dryRun` / `payment_queryInfo`.
        let mut msg = format!("submit of transaction {ledger_hex} failed: {e}");
        match dry_run_extrinsic(node_rpc_url, &ext_hex).await {
            Ok(dry_val) => {
                msg.push_str(&format!("\nMidnight system_dryRun: {dry_val}"));
            }
            Err(dry_err) => {
                msg.push_str(&format!("\nMidnight system_dryRun unavailable: {dry_err}"));
            }
        }

        match payment_query_info(node_rpc_url, &ext_hex).await {
            Ok(info) => msg.push_str(&format!("\nMidnight payment_queryInfo: {info}")),
            Err(info_err) => msg.push_str(&format!(
                "\nMidnight payment_queryInfo unavailable: {info_err}"
            )),
        }
        append_balance_overspend_hint(&mut msg);
        append_input_not_in_utxos_hint(&mut msg);
        return Err(err(msg));
    }

    Ok(ledger_hex)
}

/// Submit a sealed Midnight transaction via the node RPC — blocking wrapper around
/// [`submit_unshielded_tx`] for the synchronous `broadcast` dispatch.
pub fn broadcast_sealed(node_rpc_url: &str, signed_bytes: &[u8]) -> Result<String, std::io::Error> {
    super::block_on(submit_unshielded_tx(node_rpc_url, signed_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_ws_url_normalizes_schemes() {
        assert_eq!(
            node_ws_url("https://rpc.preview.midnight.network/").unwrap(),
            "wss://rpc.preview.midnight.network"
        );
        assert_eq!(
            node_ws_url("http://localhost:9944").unwrap(),
            "ws://localhost:9944"
        );
        // Already-ws URLs pass through (minus a trailing slash).
        assert_eq!(
            node_ws_url("wss://rpc.preview.midnight.network/").unwrap(),
            "wss://rpc.preview.midnight.network"
        );
    }

    #[test]
    fn node_http_url_strips_ws_suffix_and_scheme() {
        assert_eq!(node_http_url("wss://host/ws").unwrap(), "https://host");
        assert_eq!(
            node_http_url("https://rpc.preview.midnight.network/").unwrap(),
            "https://rpc.preview.midnight.network"
        );
    }

    #[test]
    fn ledger_error_hints_match_their_codes() {
        // Each hint appender fires only when the error text carries its ledger code or name.
        let mut msg = "submit failed: Custom error: 138".to_string();
        append_balance_overspend_hint(&mut msg);
        assert!(msg.contains("BalanceCheckOverspend"));

        let mut msg = "InputNotInUtxos".to_string();
        append_input_not_in_utxos_hint(&mut msg);
        assert!(msg.contains("no longer in the UTXO set"));

        // No spurious hint when the code is absent.
        let mut clean = "some unrelated error".to_string();
        append_balance_overspend_hint(&mut clean);
        assert_eq!(clean, "some unrelated error");
    }

    #[test]
    fn a_bad_node_url_is_reported_without_its_key() {
        let msg = node_ws_url("ftp://node.example/?apikey=KEY")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("ftp://node.example/"), "{msg}");
        assert!(!msg.contains("KEY"), "{msg}");
        let msg = require_tls_unless_loopback("http://node.example/?apikey=KEY")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("http://node.example/"), "{msg}");
        assert!(!msg.contains("KEY"), "{msg}");
    }

    #[test]
    fn plaintext_node_urls_are_refused_unless_loopback() {
        for ok in [
            "https://rpc.preview.midnight.network/",
            "wss://rpc.preview.midnight.network",
            "http://localhost:9944",
            "ws://127.0.0.1:9944",
            "http://[::1]:9944/",
        ] {
            assert!(require_tls_unless_loopback(ok).is_ok(), "{ok}");
        }
        for refused in [
            "http://rpc.preview.midnight.network/",
            "ws://10.0.0.5:9944",
            "ftp://localhost:9944",
            "localhost:9944",
        ] {
            assert!(require_tls_unless_loopback(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn an_unparsable_response_body_is_truncated() {
        let body = "x".repeat(ERROR_BODY_MAX_CHARS + 50);
        assert_eq!(truncated(&body).chars().count(), ERROR_BODY_MAX_CHARS + 1);
        assert_eq!(truncated("short"), "short");
    }

    #[test]
    fn ledger_tx_hash_rejects_non_transaction_bytes() {
        assert!(midnight_ledger_tx_hash_hex(b"not a midnight tx").is_err());
    }
}
