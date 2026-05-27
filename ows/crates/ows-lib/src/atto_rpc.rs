//! Minimal Atto Node and Work Server REST helpers.
//!
//! Uses `curl` for HTTP, consistent with the rest of ows-lib (no added HTTP deps).

use crate::error::OwsLibError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

pub type AttoHash = String;
pub type AttoInstant = i64;
pub type AttoTransaction = Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoWorkRequest {
    pub network: String,
    pub timestamp: AttoInstant,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttoWorkResponse {
    pub work: String,
}

pub struct AttoNodeClient {
    base_url: String,
}

impl AttoNodeClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: trim_base_url(base_url.into()),
        }
    }

    /// `POST /transactions/stream`, collected until the first streamed
    /// transaction. Returns the streamed hash when one is present.
    pub(crate) fn publish_transaction_value_stream(
        &self,
        transaction: &AttoTransaction,
    ) -> Result<Option<AttoHash>, OwsLibError> {
        let text = http_call(
            "POST",
            &self.url("transactions/stream"),
            Some(transaction),
            "application/x-ndjson",
        )?;
        let streamed = first_ndjson_value(&text)?;
        Ok(streamed.and_then(|value| {
            value
                .get("hash")
                .and_then(Value::as_str)
                .or_else(|| value.get("transactionHash").and_then(Value::as_str))
                .or_else(|| {
                    value
                        .get("block")
                        .and_then(|block| block.get("hash"))
                        .and_then(Value::as_str)
                })
                .map(str::to_string)
        }))
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }
}

pub struct AttoWorkServerClient {
    base_url: String,
}

impl AttoWorkServerClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: trim_base_url(base_url.into()),
        }
    }

    /// Atto Commons remote worker contract: `POST /works` with
    /// `{ network, timestamp, target }` and response `{ work }`.
    pub fn work(&self, request: &AttoWorkRequest) -> Result<AttoWorkResponse, OwsLibError> {
        let body = serde_json::to_value(request)?;
        let text = http_call(
            "POST",
            &format!("{}/works", self.base_url),
            Some(&body),
            "application/json",
        )?;
        Ok(serde_json::from_str(&text)?)
    }
}

fn trim_base_url(mut base_url: String) -> String {
    while base_url.ends_with('/') {
        base_url.pop();
    }
    base_url
}

fn first_ndjson_value(body: &str) -> Result<Option<Value>, OwsLibError> {
    body.lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(OwsLibError::from))
        .transpose()
}

fn http_call(
    method: &str,
    url: &str,
    body: Option<&Value>,
    accept: &str,
) -> Result<String, OwsLibError> {
    let is_ndjson_stream = accept == "application/x-ndjson";
    let mut args = vec![
        "-sS".to_string(),
        "-X".to_string(),
        method.to_string(),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "-H".to_string(),
        format!("Accept: {accept}"),
    ];

    if is_ndjson_stream {
        args.push("-N".to_string());
        args.push("--max-time".to_string());
        args.push("15".to_string());
    }

    let body_string;
    if let Some(body) = body {
        body_string = body.to_string();
        args.push("-d".to_string());
        args.push(body_string);
    }

    args.push("-w".to_string());
    args.push("\n%{http_code}".to_string());
    args.push(url.to_string());

    let output = Command::new("curl")
        .args(args)
        .output()
        .map_err(|e| OwsLibError::BroadcastFailed(format!("failed to run curl: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let (body, status) = stdout.rsplit_once('\n').ok_or_else(|| {
        OwsLibError::BroadcastFailed(format!(
            "Atto HTTP response missing status trailer for {method} {url}"
        ))
    })?;
    let status_code = status.trim().parse::<u16>().map_err(|e| {
        OwsLibError::BroadcastFailed(format!(
            "Atto HTTP response had invalid status trailer `{}`: {e}",
            status.trim()
        ))
    })?;

    if !output.status.success() {
        let curl_timed_out = output.status.code() == Some(28);
        if !(is_ndjson_stream && curl_timed_out && (200..300).contains(&status_code)) {
            return Err(OwsLibError::BroadcastFailed(format!(
                "Atto HTTP transport failed for {method} {url}: {stderr}"
            )));
        }
    }

    if !(200..300).contains(&status_code) {
        let trimmed = body.trim();
        let detail = if trimmed.is_empty() {
            stderr.trim()
        } else {
            trimmed
        };
        return Err(OwsLibError::BroadcastFailed(format!(
            "Atto HTTP {status_code} for {method} {url}: {detail}"
        )));
    }

    Ok(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const ADDRESS: &str = "atto://aaferyy3quqiyugpambc452bu2oqh7hrcazz4vnvem2meaa6thwf4vkiuiwyw";
    const HASH: &str = "9072A5DB95CF7866F9AF4CC4C12C01F8E1DF903A6A0660EF62986A4B6191BD0C";

    #[test]
    fn publish_transaction_stream_posts_signed_transaction_and_returns_hash() {
        let transaction = sample_transaction();
        let body = format!(
            "{}\n",
            serde_json::json!({
                "type": "SEND",
                "hash": HASH,
                "signature": "00".repeat(64),
                "work": "8E9C4A839AB702AF",
                "address": ADDRESS
            })
        );
        let (base_url, handle) = serve_once(200, "application/x-ndjson", &body);

        let client = AttoNodeClient::new(base_url);
        let hash = client
            .publish_transaction_value_stream(&transaction)
            .unwrap();
        let request = handle.join().unwrap();

        assert!(
            request.starts_with("POST /transactions/stream HTTP/1.1"),
            "{request}"
        );
        assert!(request.contains("\"type\":\"SEND\""), "{request}");
        assert!(request.contains("\"signature\""), "{request}");
        assert_eq!(hash.as_deref(), Some(HASH));
    }

    #[test]
    fn work_server_posts_works_request() {
        let response = r#"{"work":"8E9C4A839AB702AF"}"#;
        let (base_url, handle) = serve_once(200, "application/json", response);

        let client = AttoWorkServerClient::new(base_url);
        let work = client
            .work(&AttoWorkRequest {
                network: "LIVE".to_string(),
                timestamp: 1_767_390_950_000,
                target: HASH.to_string(),
            })
            .unwrap();
        let request = handle.join().unwrap();

        assert!(request.starts_with("POST /works HTTP/1.1"), "{request}");
        assert!(request.contains("\"network\":\"LIVE\""), "{request}");
        assert_eq!(work.work, "8E9C4A839AB702AF");
    }

    #[test]
    fn http_error_maps_to_broadcast_failed_with_status_and_body() {
        let (base_url, handle) =
            serve_once(400, "application/json", r#"{"error":"bad transaction"}"#);

        let client = AttoNodeClient::new(base_url);
        let err = client
            .publish_transaction_value_stream(&sample_transaction())
            .unwrap_err();
        let _ = handle.join().unwrap();

        match err {
            OwsLibError::BroadcastFailed(msg) => {
                assert!(msg.contains("HTTP 400"), "{msg}");
                assert!(msg.contains("bad transaction"), "{msg}");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    fn sample_transaction() -> Value {
        serde_json::json!({
            "type": "SEND",
            "network": "LIVE",
            "version": 0,
            "algorithm": "V1",
            "publicKey": "44C8865188D6FBE1C084436FF2E08D34538BA0FB2FCB1A8FA76F8127CCF6A281",
            "height": "2",
            "balance": "999999999999999999",
            "timestamp": 1767390950976_i64,
            "address": ADDRESS,
            "previous": HASH,
            "receiverAlgorithm": "V1",
            "receiverPublicKey": "44C8865188D6FBE1C084436FF2E08D34538BA0FB2FCB1A8FA76F8127CCF6A281",
            "receiverAddress": ADDRESS,
            "amount": "1",
            "signature": "00".repeat(64),
            "work": "8E9C4A839AB702AF"
        })
    }

    fn serve_once(
        status: u16,
        content_type: &'static str,
        body: &str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 16 * 1024];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let reason = match status {
                200 => "OK",
                400 => "Bad Request",
                _ => "Status",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (format!("http://{addr}"), handle)
    }
}
