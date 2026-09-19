use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

// Synthetic signed transaction from the Cardano signer's payment-key test vector.
// The transaction ID hashes its original body, not the full witnessed CBOR.
const SIGNED_TX: &str = "84a300d9010281825820cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe00018182581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed03031a001e8480021a000f4240a100d901028182582065a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128584081a1235ccc8c96203f379891da1041af709f532f97a73d220eb081f444622701ce5660044f8fe90ec74d3d4ad7c1c0aece569a106f08a298566c51b139285500f5f6";
const TX_ID: &str = "6c84b1c9ac839cad80b37ff528e7c6f9991de7d1b9b16055a6d8f7df0a7fa7ee";

fn submit_to_mock(status: u16, body: &str) -> Result<String, OwsLibError> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/api/v1/", listener.local_addr().unwrap());
    let signed = hex::decode(SIGNED_TX).unwrap();
    let expected_request = signed.clone();
    let response = format!(
        "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no broadcast request received");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("mock accept failed: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "request ended before its body");
            request.extend_from_slice(&chunk[..n]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap();
                assert!(headers.starts_with("POST /api/v1/submittx HTTP/1.1"));
                assert!(headers
                    .to_ascii_lowercase()
                    .contains("content-type: application/cbor"));
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                if request.len() >= end + 4 + length {
                    assert_eq!(&request[end + 4..end + 4 + length], expected_request);
                    break;
                }
            }
        }
        stream.write_all(response.as_bytes()).unwrap();
    });
    let result = broadcast_cardano(&url, &signed);
    server.join().unwrap();
    result
}

#[test]
fn cardano_broadcast_accepts_matching_json_and_bare_hashes() {
    for body in [TX_ID.to_string(), format!("\"{TX_ID}\"")] {
        assert_eq!(submit_to_mock(202, &body).unwrap(), TX_ID);
    }
}

#[test]
fn cardano_broadcast_normalizes_whitespace_and_hex_case() {
    for body in [
        format!(" \n{TX_ID}\n"),
        format!(" \n\"{}\"\n", TX_ID.to_uppercase()),
    ] {
        assert_eq!(submit_to_mock(202, &body).unwrap(), TX_ID);
    }
}

#[test]
fn cardano_broadcast_rejects_invalid_hash_responses() {
    for body in [
        String::new(),
        "bad".into(),
        "z".repeat(64),
        format!("\"{TX_ID}"),
        format!("[{TX_ID}]"),
        "é".repeat(32),
    ] {
        let err = submit_to_mock(202, &body).unwrap_err();
        assert!(matches!(err, OwsLibError::BroadcastFailed(_)), "{err}");
        assert!(
            err.to_string().contains("invalid transaction hash"),
            "{err}"
        );
    }
}

#[test]
fn cardano_broadcast_rejects_a_different_valid_transaction_id() {
    let err = submit_to_mock(202, &format!("\"{}\"", "00".repeat(32))).unwrap_err();
    assert!(
        err.to_string().contains("transaction hash mismatch"),
        "{err}"
    );
    assert!(
        err.to_string().contains(TX_ID),
        "error should include the expected ID: {err}"
    );
}

#[test]
fn cardano_broadcast_requires_accepted_status_and_preserves_rpc_error() {
    for status in [200, 400, 500] {
        let err = submit_to_mock(status, "provider rejected this transaction").unwrap_err();
        assert!(
            err.to_string()
                .contains("provider rejected this transaction"),
            "{err}"
        );
    }
}

#[test]
fn cardano_broadcast_rejects_invalid_transaction_before_network_access() {
    let err = broadcast_cardano("not-a-url", &[0x80]).unwrap_err();
    assert!(err.to_string().contains("invalid transaction"), "{err}");
}
