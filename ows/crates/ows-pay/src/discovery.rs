use crate::error::{PayError, PayErrorCode};
use crate::types::{DiscoverResult, DiscoveryResponse, Protocol, Service};

const CDP_DISCOVERY_URL: &str = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";

const TESTNETS: &[&str] = &[
    "base-sepolia",
    "eip155:84532",
    "eip155:11155111",
    "solana-devnet",
];

// ===========================================================================
// Unified discovery (public API)
// ===========================================================================

/// Discover payable services.
///
/// Fetches the x402 directory with the given pagination parameters,
/// filters testnets, and returns services with pagination metadata.
///
/// When a query is provided the upstream API does not support server-side
/// filtering, so we paginate through pages internally until we have
/// collected enough matching results (up to `limit`).
pub async fn discover_all(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<DiscoverResult, PayError> {
    let limit = limit.unwrap_or(100);
    let offset = offset.unwrap_or(0);

    if let Some(q) = query {
        // Client-side search: page through the full directory to find matches.
        return discover_with_query(q, limit, offset).await;
    }

    // No query — single page fetch.
    let resp = fetch_x402(limit, offset).await?;
    let total = resp.total;

    let services = filter_services(resp.items, None);

    Ok(DiscoverResult {
        services,
        total,
        limit,
        offset,
    })
}

/// Paginate through the upstream directory collecting services that match
/// `query` until we have `limit` results (after skipping `offset` matches).
async fn discover_with_query(
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<DiscoverResult, PayError> {
    const PAGE_SIZE: u64 = 500;
    const MAX_PAGES: u64 = 30; // safety cap: don't fetch more than 15 000 items

    let mut collected: Vec<Service> = Vec::new();
    let mut skipped: u64 = 0;
    let mut api_offset: u64 = 0;
    let mut total: u64 = 0;

    for _ in 0..MAX_PAGES {
        let resp = fetch_x402(PAGE_SIZE, api_offset).await?;
        total = resp.total;
        let page_len = resp.items.len() as u64;

        let matches = filter_services(resp.items, Some(query));
        for svc in matches {
            if skipped < offset {
                skipped += 1;
                continue;
            }
            collected.push(svc);
            if collected.len() as u64 >= limit {
                break;
            }
        }

        if collected.len() as u64 >= limit {
            break;
        }

        api_offset += page_len;
        if api_offset >= total {
            break;
        }
    }

    Ok(DiscoverResult {
        services: collected,
        total,
        limit,
        offset,
    })
}

/// Filter and convert raw discovered services, optionally matching against a
/// query string (case-insensitive, checked against URL and descriptions).
fn filter_services(
    items: Vec<crate::types::DiscoveredService>,
    query: Option<&str>,
) -> Vec<Service> {
    let q = query.map(|q| q.to_lowercase());
    let mut services = Vec::new();

    for svc in items {
        let accept = match svc.accepts.first() {
            Some(a) => a,
            None => continue,
        };

        let is_testnet = TESTNETS.iter().any(|t| accept.network.contains(t));
        if is_testnet {
            continue;
        }

        if let Some(ref q) = q {
            let url_match = svc.resource.to_lowercase().contains(q);
            let accepts_desc = accept
                .description
                .as_ref()
                .map(|d| d.to_lowercase().contains(q))
                .unwrap_or(false);
            let meta_desc = svc
                .metadata
                .as_ref()
                .and_then(|m| m.description.as_ref())
                .map(|d| d.to_lowercase().contains(q))
                .unwrap_or(false);
            if !url_match && !accepts_desc && !meta_desc {
                continue;
            }
        }

        let desc = accept
            .description
            .as_deref()
            .or_else(|| svc.metadata.as_ref().and_then(|m| m.description.as_deref()))
            .unwrap_or("");

        services.push(Service {
            protocol: Protocol::X402,
            name: svc.resource.clone(),
            url: svc.resource,
            description: truncate(desc, 80),
            price: format_price(&accept.amount, &accept.network),
            network: accept.network.clone(),
            tags: vec![],
        });
    }

    services
}

// ===========================================================================
// x402 fetching (internal)
// ===========================================================================

struct FetchResult {
    items: Vec<crate::types::DiscoveredService>,
    total: u64,
}

async fn fetch_x402(limit: u64, offset: u64) -> Result<FetchResult, PayError> {
    let client = reqwest::Client::new();
    let resp = client
        .get(CDP_DISCOVERY_URL)
        .query(&[("limit", limit.to_string()), ("offset", offset.to_string())])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::DiscoveryFailed,
            format!("x402 discovery returned {status}: {body}"),
        ));
    }

    let body: DiscoveryResponse = resp.json().await.map_err(|e| {
        PayError::new(
            PayErrorCode::DiscoveryFailed,
            format!("failed to parse x402 discovery: {e}"),
        )
    })?;

    let total = body.pagination.map(|p| p.total).unwrap_or(0);

    Ok(FetchResult {
        items: body.items,
        total,
    })
}

// ===========================================================================
// Formatting helpers
// ===========================================================================

pub(crate) fn format_price(amount_str: &str, network: &str) -> String {
    let chain_type = crate::chains::resolve_chain_type(network);
    match chain_type {
        Some(ows_core::ChainType::Nano) => format_nano(amount_str),
        _ => format_usdc(amount_str),
    }
}

pub(crate) fn format_usdc(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let whole = amount / 1_000_000;
    let frac = amount % 1_000_000;
    let frac_str = format!("{frac:06}");
    let trimmed = frac_str.trim_end_matches('0');
    let trimmed = if trimmed.is_empty() { "00" } else { trimmed };
    format!("${whole}.{trimmed}")
}

pub(crate) fn format_nano(amount_str: &str) -> String {
    let amount: u128 = amount_str.parse().unwrap_or(0);
    let divisor = 1_000_000_000_000_000_000_000_000_000_000u128;
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        format!("{whole} XNO")
    } else {
        let frac_str = format!("{frac:030}");
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed} XNO")
    }
}

fn truncate(s: &str, max: usize) -> String {
    let first_line = s.lines().next().unwrap_or("");
    if first_line.len() > max {
        let cutoff = first_line
            .char_indices()
            .map(|(idx, _)| idx)
            .chain(std::iter::once(first_line.len()))
            .take_while(|&idx| idx <= max.saturating_sub(3))
            .last()
            .unwrap_or(0);

        format!("{}...", &first_line[..cutoff])
    } else {
        first_line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // format_usdc
    // -----------------------------------------------------------------------

    #[test]
    fn format_usdc_zero() {
        assert_eq!(format_usdc("0"), "$0.00");
    }

    #[test]
    fn format_usdc_one_cent() {
        assert_eq!(format_usdc("10000"), "$0.01");
    }

    #[test]
    fn format_usdc_one_dollar() {
        assert_eq!(format_usdc("1000000"), "$1.00");
    }

    #[test]
    fn format_usdc_fractional() {
        assert_eq!(format_usdc("1500000"), "$1.5");
    }

    #[test]
    fn format_usdc_large() {
        assert_eq!(format_usdc("100000000"), "$100.00");
    }

    #[test]
    fn format_usdc_sub_cent() {
        assert_eq!(format_usdc("1"), "$0.000001");
    }

    #[test]
    fn format_usdc_non_numeric() {
        assert_eq!(format_usdc("abc"), "$0.00");
    }

    #[test]
    fn format_usdc_empty() {
        assert_eq!(format_usdc(""), "$0.00");
    }

    // -----------------------------------------------------------------------
    // format_nano
    // -----------------------------------------------------------------------

    #[test]
    fn format_nano_whole() {
        assert_eq!(format_nano("1000000000000000000000000000000"), "1 XNO");
    }

    #[test]
    fn format_nano_fractional() {
        assert_eq!(format_nano("1500000000000000000000000000000"), "1.5 XNO");
    }

    #[test]
    fn format_nano_very_small() {
        assert_eq!(format_nano("1"), "0.000000000000000000000000000001 XNO");
    }

    #[test]
    fn format_price_dispatches() {
        assert_eq!(format_price("10000", "eip155:8453"), "$0.01");
        assert_eq!(
            format_price("1000000000000000000000000000000", "nano:mainnet"),
            "1 XNO"
        );
    }

    // -----------------------------------------------------------------------
    // truncate
    // -----------------------------------------------------------------------

    #[test]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 80), "hello");
    }

    #[test]
    fn truncate_long_string() {
        let long = "a".repeat(100);
        let result = truncate(&long, 20);
        assert!(result.len() <= 20);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_long_utf8_string_respects_char_boundaries() {
        let prefix = "a".repeat(76);
        let input = format!("{prefix}“🙂 rest");
        let result = truncate(&input, 80);

        assert_eq!(result, format!("{prefix}..."));
    }

    #[test]
    fn truncate_multiline_uses_first_line() {
        assert_eq!(truncate("first\nsecond\nthird", 80), "first");
    }

    #[test]
    fn truncate_empty() {
        assert_eq!(truncate("", 80), "");
    }

    // -----------------------------------------------------------------------
    // testnet filtering (unit-level, no network)
    // -----------------------------------------------------------------------

    #[test]
    fn testnet_list_contains_expected_entries() {
        assert!(TESTNETS.contains(&"base-sepolia"));
        assert!(TESTNETS.contains(&"eip155:84532"));
        assert!(TESTNETS.contains(&"eip155:11155111"));
        assert!(TESTNETS.contains(&"solana-devnet"));
    }

    #[test]
    fn testnet_check_matches() {
        let network = "base-sepolia";
        assert!(TESTNETS.iter().any(|t| network.contains(t)));
    }

    #[test]
    fn mainnet_check_does_not_match() {
        let network = "base";
        assert!(!TESTNETS.iter().any(|t| network.contains(t)));
    }

    // -----------------------------------------------------------------------
    // discover_all (live, ignored by default)
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore]
    async fn live_discover_returns_services() {
        let result = discover_all(None, Some(10), Some(0)).await.unwrap();
        assert!(result.total > 0);
        assert!(!result.services.is_empty());
        assert_eq!(result.limit, 10);
        assert_eq!(result.offset, 0);

        // No testnets should appear.
        for svc in &result.services {
            assert!(
                !TESTNETS.iter().any(|t| svc.network.contains(t)),
                "testnet {} leaked through",
                svc.network
            );
        }
    }

    #[tokio::test]
    #[ignore]
    async fn live_discover_pagination() {
        let page1 = discover_all(None, Some(5), Some(0)).await.unwrap();
        let page2 = discover_all(None, Some(5), Some(5)).await.unwrap();

        // Pages should have same total.
        assert_eq!(page1.total, page2.total);

        // Pages should have different services (unless one is empty due to testnet filtering).
        if !page1.services.is_empty() && !page2.services.is_empty() {
            assert_ne!(page1.services[0].url, page2.services[0].url);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn live_discover_query_filters() {
        let result = discover_all(Some("heurist"), Some(50), Some(0))
            .await
            .unwrap();
        for svc in &result.services {
            let combined = format!("{} {}", svc.url, svc.description).to_lowercase();
            assert!(
                combined.contains("heurist"),
                "service should match query: {}",
                svc.url
            );
        }
    }
}
