//! Loopback listeners for tests that check where a request goes, and a way to run a request with the
//! proxy variables set without touching this process's environment.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Accept connections on a loopback port in the background, answering each with `response` and
/// counting it. The thread outlives the test, parked in `accept`.
pub(crate) fn loopback_listener(response: String) -> (SocketAddr, Arc<AtomicUsize>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = conn.read(&mut buf);
            let _ = conn.write_all(response.as_bytes());
        }
    });
    (addr, hits)
}

/// An HTTP 200 response carrying `body` as JSON.
pub(crate) fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Run the ignored test `child` in a child copy of this test binary, with `var` set to `value` and
/// every proxy variable pointing at `proxy`, so the proxy is set there from the start and this
/// process's environment is never touched. True when the child test passed.
pub(crate) fn run_child_behind_proxy(
    child: &str,
    var: &str,
    value: &str,
    proxy: SocketAddr,
) -> bool {
    let proxy_url = format!("http://{proxy}");
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([child, "--exact", "--ignored", "--nocapture"])
        .env(var, value)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy");
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env(name, &proxy_url);
    }
    command.status().unwrap().success()
}
