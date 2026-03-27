use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::chains;
use crate::error::{PayError, PayErrorCode};
use crate::types::{
    Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload,
    PaymentRequirements, Protocol, X402Response,
};
use crate::wallet::WalletAccess;

// v2 headers (current spec)
const HEADER_PAYMENT_REQUIRED_V2: &str = "payment-required";
const HEADER_PAYMENT_V2: &str = "PAYMENT-SIGNATURE";

// v1 headers (legacy)
const HEADER_PAYMENT_REQUIRED_V1: &str = "x-payment-required";
const HEADER_PAYMENT_V1: &str = "X-PAYMENT";

/// Handle x402 payment for a 402 response we already received.
pub(crate) async fn handle_x402(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let (requirements, version) = parse_requirements(resp_headers, body_402)?;
    let (req, network) = pick_payment_option(wallet, &requirements)?;

    let version_num = match version {
        X402Version::V1 => 1,
        X402Version::V2 => 2,
    };

    let (mut payload, payment_info) = build_signed_payment(wallet, req, &network)?;
    payload.x402_version = version_num;

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    let client = reqwest::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64), version)?
        .send()
        .await?;

    let status = retry.status().as_u16();
    let response_body = retry.text().await.unwrap_or_default();

    Ok(PayResult {
        protocol: Protocol::X402,
        status,
        body: response_body,
        payment: Some(payment_info),
    })
}

// ---------------------------------------------------------------------------
// Scheme dispatch
// ---------------------------------------------------------------------------

/// Build a signed payment payload, dispatching on the scheme.
fn build_signed_payment(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    match req.scheme.as_str() {
        "exact" => build_evm_exact(wallet, req, network),
        scheme => Err(PayError::new(
            PayErrorCode::ProtocolUnknown,
            format!("unsupported payment scheme: {scheme}"),
        )),
    }
}

/// Build an EVM "exact" (EIP-3009 TransferWithAuthorization) payment.
fn build_evm_exact(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    let account = wallet.account(network)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_after = now.saturating_sub(5);
    let valid_before = now + req.max_timeout_seconds;

    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, format!("rng: {e}")))?;
    let nonce_hex = format!("0x{}", hex::encode(nonce_bytes));

    let token_name = req
        .extra
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("USD Coin");
    let token_version = req
        .extra
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("2");

    let chain_id_num: u64 = chains::caip2_reference(network)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::ProtocolMalformed,
                format!("cannot extract numeric chain ID from: {network}"),
            )
        })?;

    let typed_data_json = serde_json::json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "TransferWithAuthorization": [
                { "name": "from", "type": "address" },
                { "name": "to", "type": "address" },
                { "name": "value", "type": "uint256" },
                { "name": "validAfter", "type": "uint256" },
                { "name": "validBefore", "type": "uint256" },
                { "name": "nonce", "type": "bytes32" }
            ]
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id_num.to_string(),
            "verifyingContract": req.asset
        },
        "message": {
            "from": account.address,
            "to": req.pay_to,
            "value": req.amount,
            "validAfter": valid_after.to_string(),
            "validBefore": valid_before.to_string(),
            "nonce": nonce_hex.clone()
        }
    })
    .to_string();

    let signature = wallet.sign_payload(&req.scheme, network, &typed_data_json)?;

    let eip3009 = Eip3009Payload {
        signature,
        authorization: Eip3009Authorization {
            from: account.address,
            to: req.pay_to.clone(),
            value: req.amount.clone(),
            valid_after: valid_after.to_string(),
            valid_before: valid_before.to_string(),
            nonce: nonce_hex,
        },
    };

    let payload = PaymentPayload {
        x402_version: 1,
        scheme: "exact".into(),
        network: network.to_string(),
        payload: serde_json::to_value(eip3009)?,
    };

    let amount_display = crate::discovery::format_usdc(&req.amount);
    let payment_info = PaymentInfo {
        amount: amount_display,
        network: chains::display_name(network).to_string(),
        token: "USDC".to_string(),
    };

    Ok((payload, payment_info))
}

// ---------------------------------------------------------------------------
// Requirement parsing & chain selection
// ---------------------------------------------------------------------------

/// Detected x402 protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum X402Version {
    V1,
    V2,
}

/// Parse payment requirements from 402 response, returning the detected version.
fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(Vec<PaymentRequirements>, X402Version), PayError> {
    // Try v2 header first (PAYMENT-REQUIRED).
    if let Some(reqs) = try_parse_header(headers, HEADER_PAYMENT_REQUIRED_V2) {
        return Ok((reqs, X402Version::V2));
    }

    // Try v1 header (x-payment-required).
    if let Some(reqs) = try_parse_header(headers, HEADER_PAYMENT_REQUIRED_V1) {
        return Ok((reqs, X402Version::V1));
    }

    // Fall back to response body.
    let parsed: X402Response = serde_json::from_str(body_text).map_err(|e| {
        PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("failed to parse x402 402 response: {e}"),
        )
    })?;

    if parsed.accepts.is_empty() {
        return Err(PayError::new(
            PayErrorCode::ProtocolMalformed,
            "402 response has empty accepts",
        ));
    }

    // Body-only responses: use version from body if present, otherwise v1.
    let version = match parsed.x402_version {
        Some(v) if v >= 2 => X402Version::V2,
        _ => X402Version::V1,
    };

    Ok((parsed.accepts, version))
}

/// Try to decode payment requirements from a specific header name.
fn try_parse_header(
    headers: &reqwest::header::HeaderMap,
    header_name: &str,
) -> Option<Vec<PaymentRequirements>> {
    let header_val = headers.get(header_name)?;
    let header_str = header_val.to_str().ok()?;
    let decoded = B64.decode(header_str).ok()?;
    let parsed: X402Response = serde_json::from_slice(&decoded).ok()?;
    if parsed.accepts.is_empty() {
        return None;
    }
    Some(parsed.accepts)
}

/// Payment schemes we know how to handle.
const SUPPORTED_SCHEMES: &[&str] = &["exact"];

/// Pick the first payment option whose scheme we support and whose
/// network the wallet supports. Returns the requirement and its
/// resolved CAIP-2 network string.
fn pick_payment_option<'a>(
    wallet: &dyn WalletAccess,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), PayError> {
    let supported = wallet.supported_chains();

    for req in requirements {
        if !SUPPORTED_SCHEMES.contains(&req.scheme.as_str()) {
            continue;
        }

        let chain_type = match chains::resolve_chain_type(&req.network) {
            Some(ct) => ct,
            None => continue,
        };

        if !supported.contains(&chain_type) {
            continue;
        }

        // Resolve to CAIP-2 if the server sent a human name.
        let network = match ows_core::parse_chain(&req.network) {
            Ok(c) => c.chain_id.to_string(),
            Err(_) => req.network.clone(), // Already CAIP-2 (unknown to registry but namespace matched).
        };

        return Ok((req, network));
    }

    let networks: Vec<_> = requirements.iter().map(|r| r.network.as_str()).collect();
    Err(PayError::new(
        PayErrorCode::UnsupportedChain,
        format!(
            "no supported chain in 402 response (networks: {networks:?}, wallet supports: {supported:?})"
        ),
    ))
}

pub(crate) fn build_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    body: Option<&str>,
    payment_header: Option<&str>,
    version: X402Version,
) -> Result<reqwest::RequestBuilder, PayError> {
    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        other => {
            return Err(PayError::new(
                PayErrorCode::InvalidInput,
                format!("unsupported HTTP method: {other}"),
            ))
        }
    };

    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }

    if let Some(payment) = payment_header {
        let header_name = match version {
            X402Version::V2 => HEADER_PAYMENT_V2,
            X402Version::V1 => HEADER_PAYMENT_V1,
        };
        req = req.header(header_name, payment);
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ows_core::ChainType;
    use reqwest::header::HeaderMap;

    fn base_requirement() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:8453".into(),
            amount: "10000".into(),
            asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
            pay_to: "0x1234567890abcdef1234567890abcdef12345678".into(),
            max_timeout_seconds: 60,
            extra: serde_json::json!({"name": "USD Coin", "version": "2"}),
            description: Some("test service".into()),
            resource: None,
        }
    }

    // -----------------------------------------------------------------------
    // Mock wallets
    // -----------------------------------------------------------------------

    struct EvmWallet;
    impl WalletAccess for EvmWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct SolanaWallet;
    impl WalletAccess for SolanaWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "So11111111111111111111111111111111111111112".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    struct MultiWallet;
    impl WalletAccess for MultiWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm, ChainType::Solana]
        }
        fn account(&self, _network: &str) -> Result<crate::wallet::Account, PayError> {
            Ok(crate::wallet::Account {
                address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            })
        }
        fn sign_payload(
            &self,
            _scheme: &str,
            _network: &str,
            _payload: &str,
        ) -> Result<String, PayError> {
            Ok("0xdeadbeef".into())
        }
    }

    // -----------------------------------------------------------------------
    // build_request
    // -----------------------------------------------------------------------

    #[test]
    fn build_request_valid_methods() {
        let client = reqwest::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            let result = build_request(&client, "https://example.com", method, None, None, X402Version::V2);
            assert!(result.is_ok(), "method {method} should be valid");
        }
    }

    #[test]
    fn build_request_case_insensitive() {
        let client = reqwest::Client::new();
        for method in &["get", "Post", "pUT", "dElEtE", "patch"] {
            let result = build_request(&client, "https://example.com", method, None, None, X402Version::V2);
            assert!(
                result.is_ok(),
                "method {method} should be valid (case-insensitive)"
            );
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "FOOBAR", None, None, X402Version::V2);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, PayErrorCode::InvalidInput);
        assert!(err.message.contains("FOOBAR"));
    }

    #[test]
    fn build_request_head_is_invalid() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "HEAD", None, None, X402Version::V2);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // parse_requirements
    // -----------------------------------------------------------------------

    #[test]
    fn parse_requirements_from_body() {
        let headers = HeaderMap::new();
        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xabc",
                "maxTimeoutSeconds": 30
            }]
        })
        .to_string();

        let (reqs, version) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
        assert_eq!(reqs[0].network, "eip155:8453");
        assert_eq!(version, X402Version::V1); // no version in body defaults to v1
    }

    #[test]
    fn parse_requirements_from_v2_header() {
        let x402 = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xdef"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (reqs, version) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
        assert_eq!(version, X402Version::V2);
    }

    #[test]
    fn parse_requirements_from_v1_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xdef"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", encoded.parse().unwrap());

        let (reqs, version) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
        assert_eq!(version, X402Version::V1);
    }

    #[test]
    fn parse_requirements_v2_header_takes_priority() {
        let v2 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let v1 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv1"
            }]
        });

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", B64.encode(serde_json::to_string(&v2).unwrap().as_bytes()).parse().unwrap());
        headers.insert("x-payment-required", B64.encode(serde_json::to_string(&v1).unwrap().as_bytes()).parse().unwrap());

        let (reqs, version) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs[0].pay_to, "0xv2");
        assert_eq!(version, X402Version::V2);
    }

    #[test]
    fn parse_requirements_header_fallback_to_body() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment-required", "not-valid-base64!!!".parse().unwrap());

        let body = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "1000",
                "asset": "0xaaa",
                "payTo": "0xbbb"
            }]
        })
        .to_string();

        let (reqs, _) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs[0].pay_to, "0xbbb");
    }

    #[test]
    fn parse_requirements_empty_accepts_errors() {
        let headers = HeaderMap::new();
        let body = r#"{"accepts":[]}"#;
        let err = parse_requirements(&headers, body).map(|_| ()).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    #[test]
    fn parse_requirements_bad_json_errors() {
        let headers = HeaderMap::new();
        let err = parse_requirements(&headers, "this is not json").map(|_| ()).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // pick_payment_option
    // -----------------------------------------------------------------------

    #[test]
    fn pick_evm_by_caip2() {
        let reqs = vec![base_requirement()];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.network, "eip155:8453");
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_evm_by_name() {
        let mut req = base_requirement();
        req.network = "base".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        // Human name resolved to CAIP-2.
        assert_eq!(network, "eip155:8453");
    }

    #[test]
    fn pick_skips_unsupported_namespace() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_solana_with_solana_wallet() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&SolanaWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_multi_wallet_prefers_first() {
        let evm_req = base_requirement();
        let mut sol_req = base_requirement();
        sol_req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let reqs = [sol_req, evm_req];
        let (_, network) = pick_payment_option(&MultiWallet, &reqs).unwrap();
        assert!(network.starts_with("solana:"));
    }

    #[test]
    fn pick_unknown_namespace_errors() {
        let mut req = base_requirement();
        req.network = "foochain:1".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unsupported_scheme_skipped() {
        let mut req = base_requirement();
        req.scheme = "subscription".into();
        let reqs = [req];
        let err = pick_payment_option(&EvmWallet, &reqs).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn pick_unknown_evm_chain_still_works() {
        // Chain not in KNOWN_CHAINS but namespace is recognized.
        let mut req = base_requirement();
        req.network = "eip155:999999".into();
        let reqs = [req];
        let (_, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:999999");
    }

    // -----------------------------------------------------------------------
    // build_evm_exact
    // -----------------------------------------------------------------------

    #[test]
    fn build_evm_exact_produces_valid_payload() {
        let req = base_requirement();
        let (payload, info) = build_evm_exact(&EvmWallet, &req, "eip155:8453").unwrap();

        assert_eq!(payload.scheme, "exact");
        assert_eq!(payload.network, "eip155:8453");
        assert_eq!(payload.x402_version, 1);

        let p = &payload.payload;
        assert!(p.get("signature").is_some());
        assert!(p.get("authorization").is_some());
        let auth = p.get("authorization").unwrap();
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);

        assert_eq!(info.network, "base");
        assert_eq!(info.token, "USDC");
    }

    #[test]
    fn build_evm_exact_fails_for_non_numeric_chain_id() {
        let req = base_requirement();
        let err = build_evm_exact(&EvmWallet, &req, "solana:mainnet").unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // parse → pick roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn parse_and_pick_roundtrip() {
        let body = serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "maxAmountRequired": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D",
                "maxTimeoutSeconds": 120,
                "extra": {"name": "USD Coin", "version": "2"}
            }]
        })
        .to_string();

        let headers = HeaderMap::new();
        let (reqs, _) = parse_requirements(&headers, &body).unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.pay_to, "0x7d9d1821d15B9e0b8Ab98A058361233E255E405D");
        assert_eq!(network, "eip155:8453"); // "base" resolved to CAIP-2
    }

    #[test]
    fn mock_wallet_satisfies_trait() {
        let wallet = EvmWallet;
        assert_eq!(wallet.supported_chains(), vec![ChainType::Evm]);
        let account = wallet.account("eip155:8453").unwrap();
        assert!(account.address.starts_with("0x"));
        let sig = wallet.sign_payload("exact", "eip155:8453", "{}").unwrap();
        assert_eq!(sig, "0xdeadbeef");
    }
}
