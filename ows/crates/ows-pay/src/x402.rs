use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::chains;
use crate::error::{PayError, PayErrorCode};
use crate::types::{
    Eip3009Authorization, Eip3009Payload, PayResult, PaymentInfo, PaymentPayload, PaymentPayloadV1,
    PaymentPayloadV2, PaymentRequirements, Protocol, X402Response,
};
use crate::wallet::WalletAccess;
use ows_core::ChainType;

const HEADER_PAYMENT_REQUIRED: &str = "x-payment-required";
const HEADER_PAYMENT_REQUIRED_V2: &str = "payment-required";
const HEADER_PAYMENT: &str = "X-PAYMENT";
const HEADER_PAYMENT_V2: &str = "payment-signature";

/// Handle x402 payment for a 402 response we already received.
pub(crate) async fn handle_x402(
    wallet: &dyn WalletAccess,
    url: &str,
    method: &str,
    req_body: Option<&str>,
    resp_headers: &reqwest::header::HeaderMap,
    body_402: &str,
) -> Result<PayResult, PayError> {
    let (x402_version, resource, mut requirements) = parse_requirements(resp_headers, body_402)?;

    // Try offers in preference order. An offer the wallet cannot pay with
    // (`UnsupportedChain`, returned before anything is signed or sent) drops
    // its network and we fall back to the next payable one.
    let mut skipped: Option<PayError> = None;
    let (payload, payment_info) = loop {
        let (req, network) = match pick_payment_option(wallet, &requirements) {
            Ok(picked) => picked,
            Err(err) => return Err(skipped.unwrap_or(err)),
        };
        match build_signed_payment(wallet, req, &network, x402_version, resource.clone()) {
            Ok(built) => break built,
            Err(err) if err.code == PayErrorCode::UnsupportedChain => {
                requirements.retain(|r| resolve_network(&r.network) != network);
                skipped = Some(err);
            }
            Err(err) => return Err(err),
        }
    };

    let payload_json = serde_json::to_string(&payload)?;
    let payload_b64 = B64.encode(payload_json.as_bytes());

    let client = reqwest::Client::new();
    let retry = build_request(&client, url, method, req_body, Some(&payload_b64))?
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
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    match req.scheme.as_str() {
        "exact" => match chains::resolve_chain_type(network) {
            Some(ChainType::Evm) => build_evm_exact(wallet, req, network, x402_version, resource),
            Some(ChainType::Nano) => build_nano_exact(wallet, req, network, x402_version, resource),
            _ => Err(PayError::new(
                PayErrorCode::UnsupportedChain,
                format!("\"exact\" payments are not supported on {network}"),
            )),
        },
        scheme => Err(PayError::new(
            PayErrorCode::ProtocolUnknown,
            format!("unsupported payment scheme: {scheme}"),
        )),
    }
}

/// Wrap a scheme-specific payload in the v1 or v2 envelope.
fn wrap_payload(
    req: &PaymentRequirements,
    x402_version: u32,
    resource: Option<serde_json::Value>,
    inner: serde_json::Value,
) -> PaymentPayload {
    if x402_version >= 2 {
        PaymentPayload::V2(PaymentPayloadV2 {
            x402_version,
            accepted: req.clone(),
            resource,
            payload: inner,
        })
    } else {
        PaymentPayload::V1(PaymentPayloadV1 {
            x402_version,
            scheme: req.scheme.clone(),
            network: req.network.clone(),
            payload: inner,
        })
    }
}

/// Build an EVM "exact" (EIP-3009 TransferWithAuthorization) payment.
fn build_evm_exact(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
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

    let chain_id_num = ows_core::parse_chain(network)
        .map_err(|err| PayError::new(PayErrorCode::ProtocolMalformed, err))?
        .evm_chain_id_u64()
        .map_err(|err| PayError::new(PayErrorCode::ProtocolMalformed, err))?;

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
            "nonce": &nonce_hex
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

    let inner = serde_json::to_value(eip3009)?;
    let payload = wrap_payload(req, x402_version, resource, inner);

    let amount_display = crate::discovery::format_usdc(&req.amount);
    let payment_info = PaymentInfo {
        amount: amount_display,
        network: chains::display_name(network).to_string(),
        token: "USDC".to_string(),
    };

    Ok((payload, payment_info))
}

/// Build a Nano "exact" payment.
///
/// Nano has no transfer authorization to sign, so the wallet publishes a send
/// block of `amount` raw (10^30 raw = 1 XNO) to `payTo` and the payload
/// carries its hash for the server to verify: `{ "blockHash": "<hex>" }`.
fn build_nano_exact(
    wallet: &dyn WalletAccess,
    req: &PaymentRequirements,
    network: &str,
    x402_version: u32,
    resource: Option<serde_json::Value>,
) -> Result<(PaymentPayload, PaymentInfo), PayError> {
    // Reject a bad amount before anything is sent.
    if !matches!(parsed_amount(req), Some(raw) if raw > 0) {
        return Err(PayError::new(
            PayErrorCode::ProtocolMalformed,
            format!("invalid nano amount: {:?}", req.amount),
        ));
    }

    let block_hash = wallet.send_native(network, &req.pay_to, &req.amount)?;

    let inner = serde_json::json!({ "blockHash": block_hash });
    let payload = wrap_payload(req, x402_version, resource, inner);

    let payment_info = PaymentInfo {
        amount: crate::discovery::format_nano(&req.amount),
        network: chains::display_name(network).to_string(),
        token: "XNO".to_string(),
    };

    Ok((payload, payment_info))
}

// ---------------------------------------------------------------------------
// Requirement parsing & chain selection
// ---------------------------------------------------------------------------

fn parse_requirements(
    headers: &reqwest::header::HeaderMap,
    body_text: &str,
) -> Result<(u32, Option<serde_json::Value>, Vec<PaymentRequirements>), PayError> {
    for header_name in &[HEADER_PAYMENT_REQUIRED_V2, HEADER_PAYMENT_REQUIRED] {
        if let Some(header_val) = headers.get(*header_name) {
            if let Ok(header_str) = header_val.to_str() {
                if let Ok(decoded) = B64.decode(header_str) {
                    if let Ok(parsed) = serde_json::from_slice::<X402Response>(&decoded) {
                        if !parsed.accepts.is_empty() {
                            let version = match *header_name {
                                HEADER_PAYMENT_REQUIRED_V2 => parsed.x402_version.unwrap_or(2),
                                _ => parsed.x402_version.unwrap_or(1),
                            };
                            return Ok((version, parsed.resource, parsed.accepts));
                        }
                    }
                }
            }
        }
    }

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

    Ok((
        parsed.x402_version.unwrap_or(1),
        parsed.resource,
        parsed.accepts,
    ))
}

/// Payment schemes we know how to handle.
const SUPPORTED_SCHEMES: &[&str] = &["exact"];

fn is_gateway_batched(req: &PaymentRequirements) -> bool {
    req.extra
        .get("name")
        .and_then(|v| v.as_str())
        .map(|name| name == "GatewayWalletBatched")
        .unwrap_or(false)
}

fn parsed_amount(req: &PaymentRequirements) -> Option<u128> {
    req.amount.parse().ok()
}

/// Resolve to CAIP-2 if the server sent a human name.
fn resolve_network(network: &str) -> String {
    match ows_core::parse_chain(network) {
        Ok(c) => c.chain_id.to_string(),
        Err(_) => network.to_string(), // Already CAIP-2 (unknown to registry but namespace matched).
    }
}

/// Pick the first payment option whose scheme we support and whose
/// network the wallet supports. Returns the requirement and its
/// resolved CAIP-2 network string.
fn pick_payment_option<'a>(
    wallet: &dyn WalletAccess,
    requirements: &'a [PaymentRequirements],
) -> Result<(&'a PaymentRequirements, String), PayError> {
    let supported = wallet.supported_chains();
    let mut candidates = Vec::new();

    for req in requirements {
        if !SUPPORTED_SCHEMES.contains(&req.scheme.as_str()) {
            continue;
        }

        // GatewayWalletBatched requires a pre-funded gateway wallet, which
        // this client does not currently manage.
        if is_gateway_batched(req) {
            continue;
        }

        let chain_type = match chains::resolve_chain_type(&req.network) {
            Some(ct) => ct,
            None => continue,
        };

        if !supported.contains(&chain_type) {
            continue;
        }

        candidates.push((req, resolve_network(&req.network)));
    }

    if let Some((_, first_network)) = candidates.first() {
        let mut best = &candidates[0];
        for candidate in candidates.iter().skip(1) {
            if candidate.1 != *first_network {
                break;
            }

            let current = parsed_amount(candidate.0);
            let best_amount = parsed_amount(best.0);
            if current
                .zip(best_amount)
                .map(|(a, b)| a < b)
                .unwrap_or(false)
            {
                best = candidate;
            }
        }

        return Ok((best.0, best.1.clone()));
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
        req = req
            .header(HEADER_PAYMENT, payment)
            .header(HEADER_PAYMENT_V2, payment);
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ows_core::ChainType;
    use reqwest::header::HeaderMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

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

    fn read_headers(stream: &mut std::net::TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("failed to read request: {err}"),
            }
        }

        String::from_utf8(buf).unwrap()
    }

    fn header_value(request: &str, header_name: &str) -> String {
        request
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case(header_name) {
                    Some(value.trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| panic!("missing header {header_name} in request:\n{request}"))
    }

    fn decode_payment_payload(encoded: &str) -> PaymentPayload {
        let decoded = B64.decode(encoded).unwrap();
        serde_json::from_slice(&decoded).unwrap()
    }

    fn spawn_x402_flow_server(
        payment_header_name: &str,
        payment_header_value: String,
    ) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let header_name = payment_header_name.to_string();

        let handle = thread::spawn(move || {
            let (mut initial_stream, _) = listener.accept().unwrap();
            let _initial_request = read_headers(&mut initial_stream);
            let first_response = format!(
                "HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\nConnection: close\r\n{header_name}: {payment_header_value}\r\n\r\n"
            );
            initial_stream.write_all(first_response.as_bytes()).unwrap();

            let (mut retry_stream, _) = listener.accept().unwrap();
            let retry_request = read_headers(&mut retry_stream);
            tx.send(retry_request).unwrap();

            let second_response =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            retry_stream.write_all(second_response.as_bytes()).unwrap();
        });

        (format!("http://{addr}"), rx, handle)
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

    /// Reports EVM and Nano accounts but keeps the default `send_native`,
    /// like a wallet that holds a Nano address without a way to send.
    struct EvmAndNanoAccountWallet;
    impl WalletAccess for EvmAndNanoAccountWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Evm, ChainType::Nano]
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

    const NANO_PAY_TO: &str = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3";
    const NANO_BLOCK_HASH: &str =
        "991CF190094C00F0B68E2E5F75F6BEE95A2E0BD93CEAA4A6734DB9F19B728948";

    /// EVM + Nano wallet whose `send_native` records the call instead of
    /// publishing a block, or fails with `send_error` if set.
    #[derive(Default)]
    struct NanoWallet {
        sent: std::sync::Mutex<Vec<(String, String, String)>>,
        send_error: Option<PayErrorCode>,
    }
    impl WalletAccess for NanoWallet {
        fn supported_chains(&self) -> Vec<ChainType> {
            vec![ChainType::Nano, ChainType::Evm]
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
        fn send_native(&self, network: &str, to: &str, amount: &str) -> Result<String, PayError> {
            if let Some(code) = self.send_error {
                return Err(PayError::new(code, "send failed"));
            }
            self.sent
                .lock()
                .unwrap()
                .push((network.into(), to.into(), amount.into()));
            Ok(NANO_BLOCK_HASH.into())
        }
    }

    fn nano_requirement() -> PaymentRequirements {
        PaymentRequirements {
            scheme: "exact".into(),
            network: "nano:mainnet".into(),
            amount: "1000000000000000000000000000".into(), // 0.001 XNO
            asset: "XNO".into(),
            pay_to: NANO_PAY_TO.into(),
            max_timeout_seconds: 60,
            extra: serde_json::Value::Null,
            description: None,
            resource: None,
        }
    }

    // -----------------------------------------------------------------------
    // build_request
    // -----------------------------------------------------------------------

    #[test]
    fn build_request_valid_methods() {
        let client = reqwest::Client::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(result.is_ok(), "method {method} should be valid");
        }
    }

    #[test]
    fn build_request_case_insensitive() {
        let client = reqwest::Client::new();
        for method in &["get", "Post", "pUT", "dElEtE", "patch"] {
            let result = build_request(&client, "https://example.com", method, None, None);
            assert!(
                result.is_ok(),
                "method {method} should be valid (case-insensitive)"
            );
        }
    }

    #[test]
    fn build_request_invalid_method() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "FOOBAR", None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, PayErrorCode::InvalidInput);
        assert!(err.message.contains("FOOBAR"));
    }

    #[test]
    fn build_request_head_is_invalid() {
        let client = reqwest::Client::new();
        let result = build_request(&client, "https://example.com", "HEAD", None, None);
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

        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].scheme, "exact");
        assert_eq!(reqs[0].network, "eip155:8453");
    }

    #[test]
    fn parse_requirements_from_header() {
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

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xdef");
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

        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
        assert_eq!(reqs[0].pay_to, "0xbbb");
    }

    #[test]
    fn parse_requirements_from_v2_header() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn parse_requirements_v2_header_defaults_version_to_2() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2"
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(version, 2);
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn v2_header_without_version_builds_v2_payment_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());

        let mut headers = HeaderMap::new();
        headers.insert("payment-required", encoded.parse().unwrap());

        let (version, resource, reqs) = parse_requirements(&headers, "not json").unwrap();
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        let (payload, _) =
            build_signed_payment(&EvmWallet, req, &network, version, resource).unwrap();

        match payload {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required header"),
        }
    }

    #[test]
    fn parse_requirements_v2_header_takes_priority_over_v1() {
        let x402_v2 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv2"}]
        });
        let x402_v1 = serde_json::json!({
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xaaa", "payTo": "0xv1"}]
        });
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            B64.encode(serde_json::to_string(&x402_v2).unwrap().as_bytes())
                .parse()
                .unwrap(),
        );
        headers.insert(
            "x-payment-required",
            B64.encode(serde_json::to_string(&x402_v1).unwrap().as_bytes())
                .parse()
                .unwrap(),
        );

        let (_, _, reqs) = parse_requirements(&headers, "not json").unwrap();
        assert_eq!(reqs[0].pay_to, "0xv2");
    }

    #[test]
    fn build_request_sends_both_payment_headers() {
        let client = reqwest::Client::new();
        let req = build_request(
            &client,
            "https://example.com",
            "GET",
            None,
            Some("payload123"),
        )
        .unwrap()
        .build()
        .unwrap();
        let headers = req.headers();
        assert_eq!(headers.get("X-PAYMENT").unwrap(), "payload123");
        assert_eq!(headers.get("payment-signature").unwrap(), "payload123");
    }

    #[test]
    fn parse_requirements_empty_accepts_errors() {
        let headers = HeaderMap::new();
        let body = r#"{"accepts":[]}"#;
        let err = parse_requirements(&headers, body).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    #[test]
    fn parse_requirements_bad_json_errors() {
        let headers = HeaderMap::new();
        let err = parse_requirements(&headers, "this is not json").unwrap_err();
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
    fn pick_prefers_cheapest_option_within_first_supported_network() {
        let expensive = base_requirement();
        let mut cheap = base_requirement();
        cheap.amount = "1000".into();
        let reqs = [expensive, cheap];
        let (req, network) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(network, "eip155:8453");
        assert_eq!(req.amount, "1000");
    }

    #[test]
    fn pick_skips_gateway_batched_offer() {
        let mut gateway = base_requirement();
        gateway.amount = "100".into();
        gateway.extra = serde_json::json!({
            "name": "GatewayWalletBatched",
            "version": "1"
        });

        let mut regular = base_requirement();
        regular.amount = "1000".into();

        let reqs = [gateway, regular];
        let (req, _) = pick_payment_option(&EvmWallet, &reqs).unwrap();
        assert_eq!(req.amount, "1000");
        assert_eq!(req.extra["name"], "USD Coin");
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
        let (payload, info) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 1, None).unwrap();

        let v1 = match &payload {
            PaymentPayload::V1(p) => p,
            PaymentPayload::V2(_) => panic!("expected V1"),
        };
        assert_eq!(v1.scheme, "exact");
        assert_eq!(v1.network, "eip155:8453");
        assert_eq!(v1.x402_version, 1);

        assert!(v1.payload.get("signature").is_some());
        assert!(v1.payload.get("authorization").is_some());
        let auth = &v1.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);

        assert_eq!(info.network, "base");
        assert_eq!(info.token, "USDC");
    }

    #[test]
    fn build_evm_exact_produces_valid_v2_payload() {
        let req = base_requirement();
        let resource = serde_json::json!({
            "url": "https://example.com/api",
            "description": "test",
            "mimeType": "application/json"
        });
        let (payload, _) =
            build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, Some(resource.clone())).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert_eq!(v2.accepted.scheme, req.scheme);
        assert_eq!(v2.accepted.network, req.network);
        assert_eq!(v2.accepted.pay_to, req.pay_to);
        assert_eq!(v2.resource, Some(resource));

        assert!(v2.payload.get("signature").is_some());
        let auth = &v2.payload["authorization"];
        assert_eq!(auth["from"], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(auth["to"], req.pay_to);
        assert_eq!(auth["value"], req.amount);
    }

    #[test]
    fn build_evm_exact_v2_with_no_resource() {
        let req = base_requirement();
        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None).unwrap();

        let v2 = match &payload {
            PaymentPayload::V2(p) => p,
            PaymentPayload::V1(_) => panic!("expected V2"),
        };
        assert_eq!(v2.x402_version, 2);
        assert!(v2.resource.is_none());
    }

    #[test]
    fn build_evm_exact_v2_omits_null_requirement_fields() {
        let mut req = base_requirement();
        req.extra = serde_json::Value::Null;
        req.description = None;
        req.resource = None;

        let (payload, _) = build_evm_exact(&EvmWallet, &req, "eip155:8453", 2, None).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        let accepted = &encoded["accepted"];

        assert!(accepted.get("extra").is_none());
        assert!(accepted.get("description").is_none());
        assert!(accepted.get("resource").is_none());
    }

    #[test]
    fn build_evm_exact_fails_for_non_numeric_chain_id() {
        let req = base_requirement();
        let err = build_evm_exact(&EvmWallet, &req, "solana:mainnet", 1, None).unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
    }

    // -----------------------------------------------------------------------
    // build_nano_exact
    // -----------------------------------------------------------------------

    #[test]
    fn build_nano_exact_sends_and_returns_block_hash() {
        let wallet = NanoWallet::default();
        let req = nano_requirement();
        let (payload, info) = build_nano_exact(&wallet, &req, "nano:mainnet", 1, None).unwrap();

        assert_eq!(
            *wallet.sent.lock().unwrap(),
            vec![(
                "nano:mainnet".to_string(),
                NANO_PAY_TO.to_string(),
                "1000000000000000000000000000".to_string()
            )]
        );
        let v1 = match &payload {
            PaymentPayload::V1(p) => p,
            PaymentPayload::V2(_) => panic!("expected V1"),
        };
        assert_eq!(v1.scheme, "exact");
        assert_eq!(v1.network, "nano:mainnet");
        assert_eq!(
            v1.payload,
            serde_json::json!({ "blockHash": NANO_BLOCK_HASH })
        );
        assert_eq!(info.amount, "0.001 XNO");
        assert_eq!(info.network, "nano");
        assert_eq!(info.token, "XNO");
    }

    #[test]
    fn build_nano_exact_v2_payload() {
        let req = nano_requirement();
        let (payload, _) =
            build_nano_exact(&NanoWallet::default(), &req, "nano:mainnet", 2, None).unwrap();
        let encoded = serde_json::to_value(payload).unwrap();
        assert_eq!(encoded["x402Version"], 2);
        assert_eq!(encoded["accepted"]["network"], "nano:mainnet");
        assert_eq!(encoded["accepted"]["payTo"], NANO_PAY_TO);
        assert_eq!(encoded["payload"]["blockHash"], NANO_BLOCK_HASH);
    }

    #[test]
    fn build_nano_exact_rejects_bad_amount_without_sending() {
        let wallet = NanoWallet::default();
        for amount in ["0", "", "1.5", "-1"] {
            let mut req = nano_requirement();
            req.amount = amount.into();
            let err = build_nano_exact(&wallet, &req, "nano:mainnet", 1, None).unwrap_err();
            assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
        }
        assert!(wallet.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn build_signed_payment_unsupported_exact_chain() {
        let mut req = base_requirement();
        req.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let err = build_signed_payment(&SolanaWallet, &req, &req.network, 1, None).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn default_send_native_is_unsupported() {
        let err = EvmWallet
            .send_native("nano:mainnet", NANO_PAY_TO, "1")
            .unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
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
        let (_, _, reqs) = parse_requirements(&headers, &body).unwrap();
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

    #[tokio::test]
    async fn pay_retries_v1_flow_with_v1_payload() {
        let x402 = serde_json::json!({
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv1",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("x-payment-required", encoded);

        let result = crate::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&x_payment) {
            PaymentPayload::V1(v1) => {
                assert_eq!(v1.x402_version, 1);
                assert_eq!(v1.network, "eip155:8453");
                assert_eq!(v1.payload["authorization"]["to"], "0xv1");
            }
            PaymentPayload::V2(_) => panic!("expected v1 payload for x-payment-required flow"),
        }
    }

    #[tokio::test]
    async fn pay_retries_v2_flow_with_v2_payload_without_explicit_version() {
        let resource = serde_json::json!({
            "uri": "https://api.example.com/paid"
        });
        let x402 = serde_json::json!({
            "resource": resource,
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "5000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xv2",
                "extra": {
                    "name": "USD Coin",
                    "version": "2"
                }
            }]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("payment-required", encoded);

        let result = crate::pay(&EvmWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.body, "ok");

        let x_payment = header_value(&retry_request, "X-PAYMENT");
        let payment_signature = header_value(&retry_request, "payment-signature");
        assert_eq!(x_payment, payment_signature);

        match decode_payment_payload(&payment_signature) {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.x402_version, 2);
                assert_eq!(v2.accepted.pay_to, "0xv2");
                assert_eq!(
                    v2.resource,
                    Some(serde_json::json!({"uri": "https://api.example.com/paid"}))
                );
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload for payment-required flow"),
        }
    }

    #[tokio::test]
    async fn pay_falls_back_to_evm_when_first_offer_is_nano() {
        let x402 = serde_json::json!({
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "nano:mainnet",
                    "amount": "1000000000000000000000000",
                    "asset": "XNO",
                    "payTo": "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
                },
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "5000",
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "payTo": "0xbase",
                    "extra": {"name": "USD Coin", "version": "2"}
                }
            ]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("payment-required", encoded);

        // Holds a Nano account but cannot send on Nano (default `send_native`).
        let result = crate::pay(&EvmAndNanoAccountWallet, &url, "GET", None)
            .await
            .unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.payment.unwrap().network, "base");
        match decode_payment_payload(&header_value(&retry_request, "payment-signature")) {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.accepted.network, "eip155:8453");
                assert_eq!(v2.payload["authorization"]["to"], "0xbase");
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload"),
        }
    }

    #[tokio::test]
    async fn pay_falls_back_to_evm_when_first_offer_is_solana() {
        let x402 = serde_json::json!({
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                    "amount": "5000",
                    "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                    "payTo": "So11111111111111111111111111111111111111112"
                },
                {
                    "scheme": "exact",
                    "network": "base",
                    "amount": "5000",
                    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                    "payTo": "0xbase",
                    "extra": {"name": "USD Coin", "version": "2"}
                }
            ]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("x-payment-required", encoded);

        let result = crate::pay(&MultiWallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        match decode_payment_payload(&header_value(&retry_request, "X-PAYMENT")) {
            PaymentPayload::V1(v1) => {
                assert_eq!(v1.network, "base");
                assert_eq!(v1.payload["authorization"]["to"], "0xbase");
            }
            PaymentPayload::V2(_) => panic!("expected v1 payload"),
        }
    }

    #[tokio::test]
    async fn pay_nano_exact_sends_block_hash() {
        let x402 = serde_json::json!({
            "x402Version": 2,
            "accepts": [
                serde_json::to_value(nano_requirement()).unwrap(),
                serde_json::to_value(base_requirement()).unwrap()
            ]
        });
        let encoded = B64.encode(serde_json::to_string(&x402).unwrap().as_bytes());
        let (url, rx, handle) = spawn_x402_flow_server("payment-required", encoded);

        let wallet = NanoWallet::default();
        let result = crate::pay(&wallet, &url, "GET", None).await.unwrap();
        let retry_request = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        handle.join().unwrap();

        assert_eq!(result.status, 200);
        let payment = result.payment.unwrap();
        assert_eq!(payment.token, "XNO");
        assert_eq!(payment.amount, "0.001 XNO");
        assert_eq!(wallet.sent.lock().unwrap().len(), 1);
        match decode_payment_payload(&header_value(&retry_request, "payment-signature")) {
            PaymentPayload::V2(v2) => {
                assert_eq!(v2.accepted.network, "nano:mainnet");
                assert_eq!(v2.payload["blockHash"], NANO_BLOCK_HASH);
            }
            PaymentPayload::V1(_) => panic!("expected v2 payload"),
        }
    }

    #[tokio::test]
    async fn failed_nano_send_does_not_fall_back() {
        // A send that may have reached the network must not be followed by
        // a second payment on another chain.
        let body = serde_json::json!({
            "accepts": [
                serde_json::to_value(nano_requirement()).unwrap(),
                serde_json::to_value(base_requirement()).unwrap()
            ]
        })
        .to_string();
        let wallet = NanoWallet {
            send_error: Some(PayErrorCode::SigningFailed),
            ..Default::default()
        };

        // Port 9 (discard) is never contacted: the error happens before the retry.
        let err = handle_x402(
            &wallet,
            "http://127.0.0.1:9/",
            "GET",
            None,
            &HeaderMap::new(),
            &body,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, PayErrorCode::SigningFailed);
    }

    #[tokio::test]
    async fn only_unbuildable_offers_reports_why() {
        let mut sol = base_requirement();
        sol.network = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into();
        let body = serde_json::json!({ "accepts": [sol] }).to_string();

        let err = handle_x402(
            &SolanaWallet,
            "http://127.0.0.1:9/",
            "GET",
            None,
            &HeaderMap::new(),
            &body,
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
        assert!(err.message.contains("solana:"), "{}", err.message);
    }
}
