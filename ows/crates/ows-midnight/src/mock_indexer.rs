//! An in-process stand-in for the Midnight indexer, for sync tests: it speaks graphql-transport-ws
//! on a loopback port and serves a fixed event list the way the real indexer does — a subscription
//! from `id` re-sends that event (the resume is inclusive) and everything after it, each frame
//! carrying the stream's `maxId`.

use std::sync::{Arc, Mutex};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;

/// One event of the served stream: its id and its hex-encoded `raw` payload.
pub(crate) struct MockEvent {
    pub id: i64,
    pub raw: String,
}

/// Start the mock and return the GraphQL HTTP URL to hand the sync code; the WebSocket endpoint is
/// derived from it as for the real indexer. `field` names the subscription's data field (e.g.
/// `zswapLedgerEvents`). With `cut_after`, every connection is dropped after that many events, the
/// way a flaky link or a provider that recycles long-lived sockets drops it.
pub(crate) async fn spawn(
    field: &'static str,
    events: Vec<MockEvent>,
    cut_after: Option<usize>,
) -> String {
    spawn_with_cut(field, events, cut_after).await.0
}

/// [`spawn`], also returning the cut so a test can change it between runs: setting it to `None`
/// ends an outage, and the next connection is served in full at the same URL.
// The handshake callback's error type is tungstenite's, not ours to shrink.
#[allow(clippy::result_large_err)]
pub(crate) async fn spawn_with_cut(
    field: &'static str,
    events: Vec<MockEvent>,
    cut_after: Option<usize>,
) -> (String, Arc<Mutex<Option<usize>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let url = format!(
        "http://{}/api/v4/graphql",
        listener.local_addr().expect("addr")
    );
    let events = Arc::new(events);
    let cut = Arc::new(Mutex::new(cut_after));
    let served_cut = Arc::clone(&cut);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let accepted =
                tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, mut resp: Response| {
                    resp.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "graphql-transport-ws".parse().expect("header"),
                    );
                    Ok(resp)
                })
                .await;
            // A plain HTTP request (e.g. the genesis-hash query) is not a WebSocket upgrade; it
            // fails here and the client treats the answer as unavailable.
            let Ok(ws) = accepted else {
                continue;
            };
            let cut_after = *served_cut.lock().expect("cut");
            serve(ws, field, &events, cut_after).await;
        }
    });
    (url, cut)
}

async fn serve<S>(
    mut ws: tokio_tungstenite::WebSocketStream<S>,
    field: &str,
    events: &[MockEvent],
    cut: Option<usize>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let max_id = events.last().map_or(0, |e| e.id);
    while let Some(Ok(msg)) = ws.next().await {
        let Message::Text(text) = msg else {
            continue;
        };
        let frame: serde_json::Value = serde_json::from_str(&text).expect("json frame");
        match frame["type"].as_str() {
            Some("connection_init") => {
                let ack = serde_json::json!({ "type": "connection_ack" });
                if ws.send(Message::Text(ack.to_string())).await.is_err() {
                    return;
                }
            }
            Some("subscribe") => {
                let from = frame["payload"]["variables"]["id"].as_i64().unwrap_or(0);
                for (sent, e) in events.iter().filter(|e| e.id >= from).enumerate() {
                    if cut == Some(sent) {
                        // Drop the socket mid-stream, without a close frame.
                        return;
                    }
                    let mut data = serde_json::Map::new();
                    data.insert(
                        field.to_string(),
                        serde_json::json!({
                            "id": e.id,
                            "raw": e.raw,
                            "maxId": max_id,
                            "protocolVersion": 1,
                        }),
                    );
                    let next = serde_json::json!({
                        "id": frame["id"],
                        "type": "next",
                        "payload": { "data": data },
                    });
                    if ws.send(Message::Text(next.to_string())).await.is_err() {
                        return;
                    }
                }
            }
            _ => {}
        }
    }
}
