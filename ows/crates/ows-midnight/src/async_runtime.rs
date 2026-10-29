//! Shared Tokio runtime for blocking Midnight indexer/prover/submit work.

use std::future::Future;
use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// Process-wide multi-thread runtime for synchronous Midnight call sites. Every indexer, prover and
/// node call runs on it, so it also settles the TLS provider first (see [`ensure_tls_provider`]).
pub fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        ensure_tls_provider();
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ows-midnight")
            .build()
            .expect("failed to create Midnight tokio runtime")
    })
}

/// Make `ring` the process's rustls provider unless one is already installed. midnight-base-crypto
/// 1.0.2 pulls in reqwest 0.13, which compiles rustls's `aws-lc-rs` provider next to the `ring` one the
/// rest of this crate uses. With both compiled in, rustls cannot pick a default, and the first TLS
/// client built without an explicit provider (the indexer WebSocket, the node RPC) panics. A provider
/// the host application installed first is left alone.
fn ensure_tls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// Run an async future on the shared runtime (blocking the current thread).
pub fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    runtime().block_on(future)
}
