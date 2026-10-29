//! URL helpers shared between the indexer-backed sync modules, the
//! node submission pipeline and the proof-server client.

use reqwest::Url;

/// `https://` / `http://` → `wss://` / `ws://`. Caller must reject non-http(s) schemes.
pub(super) fn http_url_to_ws_url(trimmed: &str) -> Option<String> {
    if let Some(rest) = trimmed.strip_prefix("https://") {
        Some(format!("wss://{rest}"))
    } else {
        trimmed
            .strip_prefix("http://")
            .map(|rest| format!("ws://{rest}"))
    }
}

/// `url` without the parts that can carry credentials (user info, query, fragment), for error
/// messages and cache keys: hosted indexers take their API key in the query string. `None` when
/// `url` doesn't parse.
pub(crate) fn without_credentials(url: &str) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    Some(parsed.into())
}

/// Whether `url` points at this machine: `localhost` or a loopback IP. A plaintext (`http://`,
/// `ws://`) endpoint is accepted only then, since the connection carries what that endpoint is
/// trusted with.
pub(crate) fn is_loopback(url: &Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    })
}

/// Refuse `url` when it is plaintext (`http://`, `ws://`) to another machine. Whatever the connection
/// carries, an API key in the query or the wallet's addresses, would cross the network in the clear,
/// and anyone on the path could answer in the endpoint's place. `what` names the endpoint in errors,
/// which never show the URL's credentials.
pub(crate) fn refuse_plaintext_to_remote(url: &str, what: &str) -> Result<(), std::io::Error> {
    let shown = || without_credentials(url).unwrap_or_else(|| "(unparsable URL)".to_string());
    let parsed = Url::parse(url.trim())
        .map_err(|_| std::io::Error::other(format!("invalid Midnight {what} URL: {}", shown())))?;
    match parsed.scheme() {
        "https" | "wss" => Ok(()),
        "http" | "ws" if is_loopback(&parsed) => Ok(()),
        "http" | "ws" => Err(std::io::Error::other(format!(
            "refusing the plaintext Midnight {what} URL {}: use https:// or wss://, or a loopback \
             address for a local {what}",
            shown()
        ))),
        _ => Err(std::io::Error::other(format!(
            "invalid Midnight {what} URL scheme: {}",
            shown()
        ))),
    }
}

/// Derive the GraphQL-over-WebSocket endpoint from a configured indexer URL: the GraphQL HTTP
/// endpoint's path plus `/ws`, keeping its query, which is where Midnight's indexer serves it
/// whether self-hosted or hosted behind an API key passed in the query.
///
/// Accepts:
/// - `wss://host/.../ws` (returned as-is)
/// - `https://host/.../graphql` (→ `wss://host/.../graphql/ws`; trailing `/` ignored)
/// - `https://host/api/v0?project_id=…` (→ `wss://host/api/v0/ws?project_id=…`)
pub(super) fn indexer_ws_url(indexer_url: &str) -> Result<String, std::io::Error> {
    let trimmed = indexer_url.trim_end_matches('/');
    if trimmed.starts_with("wss://") || trimmed.starts_with("ws://") {
        return Ok(trimmed.to_string());
    }

    let invalid = || {
        std::io::Error::other(format!(
            "invalid Midnight indexer URL scheme: {}",
            without_credentials(indexer_url).unwrap_or_else(|| "(unparsable URL)".to_string())
        ))
    };
    let mut url = Url::parse(indexer_url).map_err(|_| invalid())?;
    let ws_path = format!("{}/ws", url.path().trim_end_matches('/'));
    url.set_path(&ws_path);
    http_url_to_ws_url(url.as_str()).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_is_refused_unless_the_endpoint_is_local() {
        for ok in [
            "https://indexer.example/api/v4/graphql?project_id=KEY",
            "wss://indexer.example/api/v4/graphql/ws",
            "http://127.0.0.1:8088/api/v4/graphql",
            "http://localhost:8088/api/v4/graphql",
            "ws://[::1]:8088/api/v4/graphql/ws",
        ] {
            assert!(refuse_plaintext_to_remote(ok, "indexer").is_ok(), "{ok}");
        }
        let refused = refuse_plaintext_to_remote(
            "http://indexer.example/api/v4/graphql?project_id=KEY",
            "indexer",
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("plaintext"), "{refused}");
        assert!(!refused.contains("KEY"), "{refused}");
        assert!(refuse_plaintext_to_remote("ftp://indexer.example", "indexer").is_err());
        assert!(refuse_plaintext_to_remote("not a url", "indexer").is_err());
    }

    #[test]
    fn ws_url_from_https_graphql() {
        let ws = indexer_ws_url("https://example.com/api/v4/graphql").unwrap();
        assert_eq!(ws, "wss://example.com/api/v4/graphql/ws");
        let ws = indexer_ws_url("http://127.0.0.1:8088/api/v4/graphql/").unwrap();
        assert_eq!(ws, "ws://127.0.0.1:8088/api/v4/graphql/ws");
    }

    #[test]
    fn ws_url_keeps_the_query() {
        let ws = indexer_ws_url("https://indexer.example/api/v0?project_id=KEY").unwrap();
        assert_eq!(ws, "wss://indexer.example/api/v0/ws?project_id=KEY");
    }

    #[test]
    fn ws_url_passthrough() {
        let ws = indexer_ws_url("wss://example.com/api/v4/graphql/ws").unwrap();
        assert_eq!(ws, "wss://example.com/api/v4/graphql/ws");
    }

    #[test]
    fn a_bad_scheme_is_reported_without_the_query() {
        let msg = indexer_ws_url("ftp://indexer.example/api?project_id=KEY")
            .unwrap_err()
            .to_string();
        assert!(msg.contains("ftp://indexer.example/api"), "{msg}");
        assert!(!msg.contains("KEY"), "{msg}");
    }

    #[test]
    fn credentials_are_stripped() {
        assert_eq!(
            without_credentials("https://user:pass@indexer.example/api/v0?project_id=KEY#frag")
                .as_deref(),
            Some("https://indexer.example/api/v0")
        );
        assert_eq!(without_credentials("not a url"), None);
    }
}
