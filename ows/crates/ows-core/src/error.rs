use serde::{Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwsErrorCode {
    WalletNotFound,
    ChainNotSupported,
    InvalidPassphrase,
    InvalidInput,
    CaipParseError,
    PolicyDenied,
    ApiKeyNotFound,
    ApiKeyExpired,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum OwsError {
    #[error("wallet not found: {id}")]
    WalletNotFound { id: String },

    #[error("chain not supported: {chain}")]
    ChainNotSupported { chain: String },

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("invalid input: {message}")]
    InvalidInput { message: String },

    #[error("CAIP parse error: {message}")]
    CaipParseError { message: String },

    #[error("policy denied: {reason}")]
    PolicyDenied { policy_id: String, reason: String },

    #[error("API key not found")]
    ApiKeyNotFound,

    #[error("API key expired: {id}")]
    ApiKeyExpired { id: String },
}

impl OwsError {
    pub fn code(&self) -> OwsErrorCode {
        match self {
            OwsError::WalletNotFound { .. } => OwsErrorCode::WalletNotFound,
            OwsError::ChainNotSupported { .. } => OwsErrorCode::ChainNotSupported,
            OwsError::InvalidPassphrase => OwsErrorCode::InvalidPassphrase,
            OwsError::InvalidInput { .. } => OwsErrorCode::InvalidInput,
            OwsError::CaipParseError { .. } => OwsErrorCode::CaipParseError,
            OwsError::PolicyDenied { .. } => OwsErrorCode::PolicyDenied,
            OwsError::ApiKeyNotFound => OwsErrorCode::ApiKeyNotFound,
            OwsError::ApiKeyExpired { .. } => OwsErrorCode::ApiKeyExpired,
        }
    }
}

#[derive(Serialize)]
struct ErrorPayload {
    code: OwsErrorCode,
    message: String,
}

impl Serialize for OwsError {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let payload = ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        };
        payload.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_mapping_wallet_not_found() {
        let err = OwsError::WalletNotFound {
            id: "abc".to_string(),
        };
        assert_eq!(err.code(), OwsErrorCode::WalletNotFound);
    }

    #[test]
    fn test_code_mapping_all_variants() {
        assert_eq!(
            OwsError::ChainNotSupported { chain: "x".into() }.code(),
            OwsErrorCode::ChainNotSupported
        );
        assert_eq!(
            OwsError::InvalidPassphrase.code(),
            OwsErrorCode::InvalidPassphrase
        );
        assert_eq!(
            OwsError::InvalidInput {
                message: "x".into()
            }
            .code(),
            OwsErrorCode::InvalidInput
        );
        assert_eq!(
            OwsError::CaipParseError {
                message: "x".into()
            }
            .code(),
            OwsErrorCode::CaipParseError
        );
        assert_eq!(
            OwsError::PolicyDenied {
                policy_id: "x".into(),
                reason: "x".into()
            }
            .code(),
            OwsErrorCode::PolicyDenied
        );
        assert_eq!(
            OwsError::ApiKeyNotFound.code(),
            OwsErrorCode::ApiKeyNotFound
        );
        assert_eq!(
            OwsError::ApiKeyExpired { id: "x".into() }.code(),
            OwsErrorCode::ApiKeyExpired
        );
    }

    #[test]
    fn test_display_output() {
        let err = OwsError::WalletNotFound {
            id: "abc-123".to_string(),
        };
        assert_eq!(err.to_string(), "wallet not found: abc-123");
    }

    #[test]
    fn test_json_serialization_shape() {
        let err = OwsError::WalletNotFound {
            id: "abc-123".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "WALLET_NOT_FOUND");
        assert_eq!(json["message"], "wallet not found: abc-123");
    }

    #[test]
    fn test_caip_parse_error_serialization() {
        let err = OwsError::CaipParseError {
            message: "bad format".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "CAIP_PARSE_ERROR");
        assert!(json["message"].as_str().unwrap().contains("bad format"));
    }

    #[test]
    fn test_policy_denied_serialization() {
        let err = OwsError::PolicyDenied {
            policy_id: "spending-limit".into(),
            reason: "exceeded daily limit".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "POLICY_DENIED");
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("exceeded daily limit"));
    }

    #[test]
    fn test_api_key_not_found_serialization() {
        let err = OwsError::ApiKeyNotFound;
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "API_KEY_NOT_FOUND");
    }

    #[test]
    fn test_api_key_expired_serialization() {
        let err = OwsError::ApiKeyExpired {
            id: "key-123".into(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "API_KEY_EXPIRED");
        assert!(json["message"].as_str().unwrap().contains("key-123"));
    }
}
