use ows_signer::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("guardian config not found for wallet: '{0}'")]
    ConfigNotFound(String),

    #[error("recovery not found for wallet: '{0}'")]
    RecoveryNotFound(String),

    #[error("recovery already active for wallet: '{0}'")]
    RecoveryAlreadyActive(String),

    #[error("recovery is frozen for wallet: '{0}'")]
    RecoveryFrozen(String),

    #[error("recovery is time locked until {0}")]
    TimeLocked(String),

    #[error("guardian not found: '{0}'")]
    GuardianNotFound(String),

    #[error("duplicate shard from guardian: '{0}'")]
    DuplicateShard(String),

    #[error("threshold not met: have {have}, need {need}")]
    ThresholdNotMet { have: usize, need: usize },

    #[error("secret hash mismatch after reconstruction")]
    SecretHashMismatch,

    #[error("shamir split failed: {0}")]
    ShamirSplitFailed(String),

    #[error("shamir reconstruct failed: {0}")]
    ShamirReconstructFailed(String),

    #[error("invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("heartbeat expired for wallet: '{0}'")]
    HeartbeatExpired(String),

    #[error("{0}")]
    Crypto(#[from] CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
