use crate::error::OwsError;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// CAIP-2 Chain ID: `namespace:reference`
#[derive(Debug, Clone, Eq)]
pub struct ChainId {
    pub namespace: String,
    pub reference: String,
}

impl ChainId {
    fn validate_namespace(ns: &str) -> Result<(), OwsError> {
        if ns.len() < 3 || ns.len() > 8 {
            return Err(OwsError::CaipParseError {
                message: format!(
                    "namespace must be 3-8 characters, got {} ('{}')",
                    ns.len(),
                    ns
                ),
            });
        }
        if !ns
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        {
            return Err(OwsError::CaipParseError {
                message: format!("namespace must be [a-z0-9], got '{}'", ns),
            });
        }
        Ok(())
    }

    fn validate_reference(reference: &str) -> Result<(), OwsError> {
        if reference.is_empty() || reference.len() > 64 {
            return Err(OwsError::CaipParseError {
                message: format!(
                    "reference must be 1-64 characters, got {} ('{}')",
                    reference.len(),
                    reference
                ),
            });
        }
        if !reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(OwsError::CaipParseError {
                message: format!("reference contains invalid characters: '{}'", reference),
            });
        }
        Ok(())
    }
}

impl FromStr for ChainId {
    type Err = OwsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(OwsError::CaipParseError {
                message: format!("expected 'namespace:reference', got '{}'", s),
            });
        }
        let namespace = parts[0].to_string();
        let reference = parts[1].to_string();
        Self::validate_namespace(&namespace)?;
        Self::validate_reference(&reference)?;
        Ok(ChainId {
            namespace,
            reference,
        })
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

impl PartialEq for ChainId {
    fn eq(&self, other: &Self) -> bool {
        self.namespace == other.namespace && self.reference == other.reference
    }
}

impl Hash for ChainId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.reference.hash(state);
    }
}

impl Serialize for ChainId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ChainId::from_str(&s).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_evm_chain_id() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.namespace, "eip155");
        assert_eq!(id.reference, "1");
    }

    #[test]
    fn test_parse_solana_chain_id() {
        let id: ChainId = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".parse().unwrap();
        assert_eq!(id.namespace, "solana");
    }

    #[test]
    fn test_parse_cosmos_chain_id() {
        let id: ChainId = "cosmos:cosmoshub-4".parse().unwrap();
        assert_eq!(id.namespace, "cosmos");
        assert_eq!(id.reference, "cosmoshub-4");
    }

    #[test]
    fn test_parse_bitcoin_chain_id() {
        let id: ChainId = "bip122:000000000019d6689c085ae165831e93".parse().unwrap();
        assert_eq!(id.namespace, "bip122");
    }

    #[test]
    fn test_parse_tron_chain_id() {
        let id: ChainId = "tron:mainnet".parse().unwrap();
        assert_eq!(id.namespace, "tron");
        assert_eq!(id.reference, "mainnet");
    }

    #[test]
    fn test_reject_empty_namespace() {
        assert!("".parse::<ChainId>().is_err());
    }

    #[test]
    fn test_reject_short_namespace() {
        assert!("ab:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn test_reject_long_namespace() {
        assert!("abcdefghi:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn test_reject_uppercase_namespace() {
        assert!("EIP155:1".parse::<ChainId>().is_err());
    }

    #[test]
    fn test_reject_no_colon() {
        assert!("eip1551".parse::<ChainId>().is_err());
    }

    #[test]
    fn test_display_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        assert_eq!(id.to_string(), "eip155:1");
        let id2: ChainId = id.to_string().parse().unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_serde_roundtrip() {
        let id: ChainId = "eip155:1".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"eip155:1\"");
        let id2: ChainId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, id2);
    }

    #[test]
    fn test_chain_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        let id1: ChainId = "eip155:1".parse().unwrap();
        let id2: ChainId = "eip155:1".parse().unwrap();
        set.insert(id1);
        assert!(set.contains(&id2));
    }
}
