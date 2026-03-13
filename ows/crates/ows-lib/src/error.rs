use ows_signer::hd::HdError;
use ows_signer::mnemonic::MnemonicError;
use ows_signer::{CryptoError, SignerError};

/// Unified error type for ows-lib operations.
#[derive(Debug, thiserror::Error)]
pub enum OwsLibError {
    #[error("wallet not found: '{0}'")]
    WalletNotFound(String),

    #[error("ambiguous wallet name '{name}' matches {count} wallets; use the wallet ID instead")]
    AmbiguousWallet { name: String, count: usize },

    #[error("wallet name already exists: '{0}'")]
    WalletNameExists(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("{0}")]
    Crypto(#[from] CryptoError),

    #[error("{0}")]
    Signer(#[from] SignerError),

    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),

    #[error("{0}")]
    Hd(#[from] HdError),

    #[error("{0}")]
    Core(#[from] ows_core::OwsError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
