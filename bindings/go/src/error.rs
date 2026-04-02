//! Error codes for the Go FFI layer.

/// Error codes returned by `ows_go_get_last_error_code()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum OwsGoError {
    Ok = 0,
    WalletNotFound = 1,
    WalletAmbiguous = 2,
    WalletExists = 3,
    InvalidInput = 4,
    BroadcastFailed = 5,
    Crypto = 6,
    Signer = 7,
    Mnemonic = 8,
    Hd = 9,
    Core = 10,
    Io = 11,
    Json = 12,
    Unknown = 99,
}

impl OwsGoError {
    /// Classify an error message string into an error code.
    #[must_use]
    pub fn from_error_msg(msg: &str) -> Self {
        if msg.contains("wallet not found") {
            Self::WalletNotFound
        } else if msg.contains("ambiguous wallet") {
            Self::WalletAmbiguous
        } else if msg.contains("wallet name already exists") {
            Self::WalletExists
        } else if msg.contains("invalid input") {
            Self::InvalidInput
        } else if msg.contains("broadcast failed") {
            Self::BroadcastFailed
        } else if msg.contains("crypto") {
            Self::Crypto
        } else if msg.contains("signer error") {
            Self::Signer
        } else if msg.contains("mnemonic") {
            Self::Mnemonic
        } else if msg.contains(" HD ") || msg.contains("HD derivation") {
            Self::Hd
        } else if msg.contains("core error") || msg.contains("OwsError") {
            Self::Core
        } else if msg.contains("I/O") || msg.contains("io error") {
            Self::Io
        } else if msg.contains("JSON") {
            Self::Json
        } else {
            Self::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_not_found() {
        assert_eq!(
            OwsGoError::from_error_msg("wallet not found: 'my-wallet'"),
            OwsGoError::WalletNotFound
        );
    }

    #[test]
    fn test_wallet_ambiguous() {
        assert_eq!(
            OwsGoError::from_error_msg("ambiguous wallet name 'test' matches 2 wallets"),
            OwsGoError::WalletAmbiguous
        );
    }

    #[test]
    fn test_wallet_exists() {
        assert_eq!(
            OwsGoError::from_error_msg("wallet name already exists: 'my-wallet'"),
            OwsGoError::WalletExists
        );
    }

    #[test]
    fn test_invalid_input() {
        assert_eq!(
            OwsGoError::from_error_msg("invalid input: empty name"),
            OwsGoError::InvalidInput
        );
    }

    #[test]
    fn test_io_error() {
        assert_eq!(
            OwsGoError::from_error_msg("I/O error: No such file"),
            OwsGoError::Io
        );
    }

    #[test]
    fn test_unknown() {
        assert_eq!(
            OwsGoError::from_error_msg("some totally unexpected error"),
            OwsGoError::Unknown
        );
    }
}
