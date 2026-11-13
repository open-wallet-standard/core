//! Fetch on-chain `LedgerParameters` via the indexer's `block` GraphQL query.
//!
//! Returned by the indexer as a hex-encoded SCALE blob; we decode it via the
//! ledger crate's tagged-deserialization so callers get a fully typed
//! [`midnight_ledger::structure::LedgerParameters`].

use midnight_serialize::tagged_deserialize;
use serde::Deserialize;
use std::sync::OnceLock;

use super::midnight_env;

#[derive(Debug, Deserialize)]
struct IndexerBlockData {
    #[allow(dead_code)]
    height: i64,
    #[allow(dead_code)]
    hash: String,
    #[serde(rename = "ledgerParameters")]
    ledger_parameters: String,
    timestamp: serde_json::Value,
}

/// The error for ledger bytes the network served that failed to decode. Bytes whose Midnight header
/// tag is a later version than the one this build expects come from a ledger it was not built
/// against, which no retry or resync can read, so the error tells the user to upgrade OWS.
pub(crate) fn network_decode_error(what: &str, e: impl std::fmt::Display) -> std::io::Error {
    let detail = e.to_string();
    if network_tag_is_later(&detail) {
        std::io::Error::other(format!(
            "{what}: {detail}. The network runs a later Midnight ledger than this OWS build \
             supports; upgrade OWS to a release built for the network's ledger"
        ))
    } else {
        std::io::Error::other(format!("{what}: {detail}"))
    }
}

/// Whether a header-tag mismatch, `expected header tag 'midnight:<kind>[v<A>]:', got
/// 'midnight:<kind>[v<B>]…'`, names a later version `B` of the same kind. The decoder reads only as
/// many bytes as the expected tag, so a longer `B` arrives cut off: digits up to the closing quote.
fn network_tag_is_later(detail: &str) -> bool {
    let tag = |marker: &str| -> Option<(&str, &str, char)> {
        let rest = &detail[detail.find(marker)? + marker.len()..];
        let open = rest.find("[v")?;
        let digits = &rest[open + 2..];
        let end = digits.find(|c: char| !c.is_ascii_digit())?;
        Some((&rest[..open], &digits[..end], digits[end..].chars().next()?))
    };
    let (Some((kind, expected, _)), Some((got_kind, got, after))) =
        (tag("expected header tag 'midnight:"), tag("got 'midnight:"))
    else {
        return false;
    };
    if kind != got_kind || got.is_empty() {
        return false;
    }
    match (after, expected.parse::<u64>(), got.parse::<u64>()) {
        (']', Ok(expected), Ok(got)) => got > expected,
        ('\'', Ok(_), _) => true,
        _ => false,
    }
}

pub(crate) fn parse_indexer_timestamp_secs(v: &serde_json::Value) -> Option<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else if let Some(s) = v.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    // Indexer docs say seconds, but some deployments return milliseconds.
    // Heuristic: anything >= year 33658 in seconds is definitely ms.
    if n >= 1_000_000_000_000 {
        Some(n / 1000)
    } else {
        Some(n)
    }
}

#[derive(Debug, Deserialize)]
struct IndexerBlockResp {
    block: Option<IndexerBlockData>,
}

#[derive(Debug, Deserialize)]
struct IndexerGraphqlResp<T> {
    data: Option<T>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightData {
    height: i64,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHeightResp {
    block: Option<IndexerBlockHeightData>,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHashData {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct IndexerBlockHashResp {
    block: Option<IndexerBlockHashData>,
}

static INDEXER_HTTP: OnceLock<reqwest::Client> = OnceLock::new();
static LOOPBACK_INDEXER_HTTP: OnceLock<reqwest::Client> = OnceLock::new();

/// Shared HTTP client for the Midnight indexer GraphQL at `indexer_url` (bounded request timeout).
///
/// An indexer on this machine is reached directly, never through a proxy named in the environment
/// (`HTTP_PROXY`, `ALL_PROXY`): its endpoint is plaintext, so that proxy would receive its queries and
/// could answer them in its place, and reqwest makes no exception for loopback hosts. Any other
/// indexer keeps the environment's proxy, which some deployments need to reach the network at all;
/// over https the proxy only relays the encrypted connection.
pub fn indexer_http_client(indexer_url: &str) -> &'static reqwest::Client {
    let loopback = reqwest::Url::parse(indexer_url).is_ok_and(|url| crate::urls::is_loopback(&url));
    let (cell, builder) = if loopback {
        (
            &LOOPBACK_INDEXER_HTTP,
            reqwest::Client::builder().no_proxy(),
        )
    } else {
        (&INDEXER_HTTP, reqwest::Client::builder())
    };
    cell.get_or_init(|| {
        builder
            .timeout(midnight_env::indexer_http_timeout())
            .build()
            .expect("the indexer client needs only the TLS backend reqwest::Client::new needs")
    })
}

/// Latest indexer block: on-chain ledger parameters and chain timestamp (unix seconds).
pub async fn fetch_indexer_tip(
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    fetch_indexer_tip_with_client(indexer_http_client(indexer_url), indexer_url).await
}

pub async fn fetch_indexer_tip_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<(midnight_ledger::structure::LedgerParameters, u64), std::io::Error> {
    let q = r#"query BlockHash($offset: BlockOffset) { block(offset: $offset) { height hash ledgerParameters timestamp } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    let block = parsed
        .data
        .and_then(|d| d.block)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))?;
    let timestamp_secs = parse_indexer_timestamp_secs(&block.timestamp)
        .ok_or_else(|| std::io::Error::other("indexer did not return block.timestamp"))?;
    let lp_hex = block.ledger_parameters;

    let raw = hex::decode(lp_hex.strip_prefix("0x").unwrap_or(lp_hex.as_str()))
        .map_err(|e| std::io::Error::other(format!("invalid ledgerParameters hex: {e}")))?;
    let mut r: &[u8] = &raw;
    let ledger_parameters =
        tagged_deserialize::<midnight_ledger::structure::LedgerParameters>(&mut r)
            .map_err(|e| network_decode_error("failed to decode ledger parameters", e))?;
    Ok((ledger_parameters, timestamp_secs))
}

/// Current indexer chain-tip block height (HTTP `block { height }`).
pub async fn fetch_indexer_block_height(indexer_url: &str) -> Result<i64, std::io::Error> {
    fetch_indexer_block_height_with_client(indexer_http_client(indexer_url), indexer_url).await
}

pub async fn fetch_indexer_block_height_with_client(
    client: &reqwest::Client,
    indexer_url: &str,
) -> Result<i64, std::io::Error> {
    let q = r#"query BlockHeight($offset: BlockOffset) { block(offset: $offset) { height } }"#;
    let resp = client
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": null }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockHeightResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.height)
        .ok_or_else(|| std::io::Error::other("indexer did not return block"))
}

/// Hash of the indexer's genesis block (HTTP `block(offset: { height: 0 }) { hash }`). It names the
/// chain instance behind a network id, which a testnet reset replaces while keeping the id.
pub async fn fetch_indexer_genesis_hash(indexer_url: &str) -> Result<String, std::io::Error> {
    let q = r#"query GenesisHash($offset: BlockOffset) { block(offset: $offset) { hash } }"#;
    let resp = indexer_http_client(indexer_url)
        .post(indexer_url)
        .json(&serde_json::json!({
            "query": q,
            "variables": { "offset": { "height": 0 } }
        }))
        .send()
        .await
        .map_err(|e| std::io::Error::other(format!("indexer query failed: {}", e.without_url())))?;

    let status = resp.status();
    let body = resp.text().await.map_err(|e| {
        std::io::Error::other(format!("indexer read body failed: {}", e.without_url()))
    })?;
    if !status.is_success() {
        return Err(std::io::Error::other(format!(
            "indexer returned {status}: {body}"
        )));
    }

    let parsed: IndexerGraphqlResp<IndexerBlockHashResp> = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::other(format!("invalid indexer json: {e}")))?;
    if let Some(errs) = parsed.errors {
        return Err(std::io::Error::other(format!(
            "indexer GraphQL error: {errs:?}"
        )));
    }
    parsed
        .data
        .and_then(|d| d.block)
        .map(|b| b.hash)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| std::io::Error::other("indexer did not return the genesis block"))
}

pub async fn fetch_indexer_ledger_parameters(
    indexer_url: &str,
) -> Result<midnight_ledger::structure::LedgerParameters, std::io::Error> {
    Ok(fetch_indexer_tip(indexer_url).await?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_net::{json_response, loopback_listener, run_child_behind_proxy};
    use std::sync::atomic::Ordering;

    const CHILD_INDEXER_VAR: &str = "OWS_TEST_INDEXER_CHILD_URL";

    #[test]
    fn bytes_from_a_later_ledger_say_to_upgrade_ows() {
        let decode = |bytes: &[u8]| {
            let err =
                tagged_deserialize::<midnight_ledger::structure::LedgerParameters>(&mut &bytes[..])
                    .unwrap_err();
            network_decode_error("failed to decode ledger parameters", err).to_string()
        };
        let tag =
            <midnight_ledger::structure::LedgerParameters as midnight_serialize::Tagged>::tag();
        let ours: u64 = tag
            .trim_start_matches("ledger-parameters[v")
            .trim_end_matches(']')
            .parse()
            .unwrap();
        for later in [
            format!("midnight:ledger-parameters[v{}]:", ours + 1),
            "midnight:ledger-parameters[v999]:".to_string(),
        ] {
            let msg = decode(later.as_bytes());
            assert!(msg.contains("expected header tag"), "{msg}");
            assert!(msg.contains("upgrade OWS"), "{msg}");
        }

        for not_later in [
            &b"midnight:ledger-parameters[v0]:"[..],
            &b"<html>bad gateway</html>"[..],
        ] {
            let msg = decode(not_later);
            assert!(msg.contains("expected header tag"), "{msg}");
            assert!(!msg.contains("upgrade OWS"), "{msg}");
        }
    }

    /// An indexer on this machine is plaintext, so a proxy named in the environment must not get its
    /// queries: it could answer them in the indexer's place. Any other indexer keeps that proxy, which
    /// some deployments need. The requests run in a child copy of this test binary with the proxy
    /// variables set.
    #[test]
    fn only_a_remote_indexer_goes_through_the_environments_proxy() {
        let (proxy, proxy_hits) =
            loopback_listener(json_response(r#"{"data":{"block":{"height":7}}}"#));
        let (indexer, indexer_hits) =
            loopback_listener(json_response(r#"{"data":{"block":{"height":42}}}"#));

        assert!(
            run_child_behind_proxy(
                "ledger_params::tests::indexer_requests_from_child",
                CHILD_INDEXER_VAR,
                &format!("http://{indexer}/api/v3/graphql"),
                proxy,
            ),
            "the child's requests did not end where they should"
        );
        assert_eq!(
            indexer_hits.load(Ordering::SeqCst),
            1,
            "the loopback indexer was not asked"
        );
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            1,
            "the remote request skipped the proxy"
        );
    }

    /// The child half of the test above; a no-op when run on its own.
    #[test]
    #[ignore = "run by only_a_remote_indexer_goes_through_the_environments_proxy"]
    fn indexer_requests_from_child() {
        let Ok(loopback) = std::env::var(CHILD_INDEXER_VAR) else {
            return;
        };
        assert_eq!(
            crate::block_on(fetch_indexer_block_height(&loopback)).unwrap(),
            42
        );
        let remote = "http://indexer.invalid/api/v3/graphql";
        assert_eq!(
            crate::block_on(fetch_indexer_block_height(remote)).unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn a_failed_request_does_not_echo_the_url() {
        // A port that was just released refuses the connection.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("bind")
            .port();
        let url = format!("http://127.0.0.1:{port}/api/v4/graphql?project_id=SECRET");
        let err = fetch_indexer_block_height(&url)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.starts_with("indexer query failed"), "{err}");
        assert!(!err.contains("SECRET"), "{err}");
    }
}
