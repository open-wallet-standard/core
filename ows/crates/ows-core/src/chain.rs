use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Tron,
    Ton,
    Spark,
    Filecoin,
    Sui,
}

/// All supported chain families, used for universal wallet derivation.
pub const ALL_CHAIN_TYPES: [ChainType; 8] = [
    ChainType::Evm,
    ChainType::Solana,
    ChainType::Bitcoin,
    ChainType::Cosmos,
    ChainType::Tron,
    ChainType::Ton,
    ChainType::Filecoin,
    ChainType::Sui,
];

/// A specific chain (e.g. "ethereum", "arbitrum") with its family type and CAIP-2 ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub name: &'static str,
    pub chain_type: ChainType,
    pub chain_id: &'static str,
}

/// Known chains registry.
pub const KNOWN_CHAINS: &[Chain] = &[
    Chain {
        name: "ethereum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:1",
    },
    Chain {
        name: "polygon",
        chain_type: ChainType::Evm,
        chain_id: "eip155:137",
    },
    Chain {
        name: "arbitrum",
        chain_type: ChainType::Evm,
        chain_id: "eip155:42161",
    },
    Chain {
        name: "optimism",
        chain_type: ChainType::Evm,
        chain_id: "eip155:10",
    },
    Chain {
        name: "base",
        chain_type: ChainType::Evm,
        chain_id: "eip155:8453",
    },
    Chain {
        name: "bsc",
        chain_type: ChainType::Evm,
        chain_id: "eip155:56",
    },
    Chain {
        name: "avalanche",
        chain_type: ChainType::Evm,
        chain_id: "eip155:43114",
    },
    Chain {
        name: "solana",
        chain_type: ChainType::Solana,
        chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    },
    Chain {
        name: "bitcoin",
        chain_type: ChainType::Bitcoin,
        chain_id: "bip122:000000000019d6689c085ae165831e93",
    },
    Chain {
        name: "cosmos",
        chain_type: ChainType::Cosmos,
        chain_id: "cosmos:cosmoshub-4",
    },
    Chain {
        name: "tron",
        chain_type: ChainType::Tron,
        chain_id: "tron:mainnet",
    },
    Chain {
        name: "ton",
        chain_type: ChainType::Ton,
        chain_id: "ton:mainnet",
    },
    Chain {
        name: "spark",
        chain_type: ChainType::Spark,
        chain_id: "spark:mainnet",
    },
    Chain {
        name: "filecoin",
        chain_type: ChainType::Filecoin,
        chain_id: "fil:mainnet",
    },
    Chain {
        name: "sui",
        chain_type: ChainType::Sui,
        chain_id: "sui:mainnet",
    },
];

/// Parse a chain string into a `Chain`. Accepts:
/// - Friendly names: "ethereum", "arbitrum", "solana", etc.
/// - CAIP-2 chain IDs: "eip155:1", "eip155:42161", etc.
/// - Legacy family names for backward compat: "evm" → resolves to ethereum
pub fn parse_chain(s: &str) -> Result<Chain, String> {
    let lower = s.to_lowercase();

    // Legacy family name backward compat
    let lookup = match lower.as_str() {
        "evm" => "ethereum",
        _ => &lower,
    };

    // Try friendly name match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.name == lookup) {
        return Ok(*chain);
    }

    // Try CAIP-2 chain ID match
    if let Some(chain) = KNOWN_CHAINS.iter().find(|c| c.chain_id == s) {
        return Ok(*chain);
    }

    Err(format!(
        "unknown chain: '{}'. Use a chain name (ethereum, solana, bitcoin, ...) or CAIP-2 ID (eip155:1, ...)",
        s
    ))
}

/// Returns the default `Chain` for a given `ChainType` (first match in registry).
pub fn default_chain_for_type(ct: ChainType) -> Chain {
    *KNOWN_CHAINS.iter().find(|c| c.chain_type == ct).unwrap()
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    pub fn namespace(&self) -> &'static str {
        match self {
            ChainType::Evm => "eip155",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bip122",
            ChainType::Tron => "tron",
            ChainType::Ton => "ton",
            ChainType::Spark => "spark",
            ChainType::Filecoin => "fil",
            ChainType::Sui => "sui",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    pub fn default_coin_type(&self) -> u32 {
        match self {
            ChainType::Evm => 60,
            ChainType::Solana => 501,
            ChainType::Cosmos => 118,
            ChainType::Bitcoin => 0,
            ChainType::Tron => 195,
            ChainType::Ton => 607,
            ChainType::Spark => 8797555,
            ChainType::Filecoin => 461,
            ChainType::Sui => 784,
        }
    }

    /// Returns the ChainType for a given CAIP-2 namespace.
    pub fn from_namespace(ns: &str) -> Option<ChainType> {
        match ns {
            "eip155" => Some(ChainType::Evm),
            "solana" => Some(ChainType::Solana),
            "cosmos" => Some(ChainType::Cosmos),
            "bip122" => Some(ChainType::Bitcoin),
            "tron" => Some(ChainType::Tron),
            "ton" => Some(ChainType::Ton),
            "spark" => Some(ChainType::Spark),
            "fil" => Some(ChainType::Filecoin),
            "sui" => Some(ChainType::Sui),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ChainType::Evm => "evm",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bitcoin",
            ChainType::Tron => "tron",
            ChainType::Ton => "ton",
            ChainType::Spark => "spark",
            ChainType::Filecoin => "filecoin",
            ChainType::Sui => "sui",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(ChainType::Evm),
            "solana" => Ok(ChainType::Solana),
            "cosmos" => Ok(ChainType::Cosmos),
            "bitcoin" => Ok(ChainType::Bitcoin),
            "tron" => Ok(ChainType::Tron),
            "ton" => Ok(ChainType::Ton),
            "spark" => Ok(ChainType::Spark),
            "filecoin" => Ok(ChainType::Filecoin),
            "sui" => Ok(ChainType::Sui),
            _ => Err(format!("unknown chain type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip() {
        let chain = ChainType::Evm;
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, "\"evm\"");
        let chain2: ChainType = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_serde_all_variants() {
        for (chain, expected) in [
            (ChainType::Evm, "\"evm\""),
            (ChainType::Solana, "\"solana\""),
            (ChainType::Cosmos, "\"cosmos\""),
            (ChainType::Bitcoin, "\"bitcoin\""),
            (ChainType::Tron, "\"tron\""),
            (ChainType::Ton, "\"ton\""),
            (ChainType::Spark, "\"spark\""),
            (ChainType::Filecoin, "\"filecoin\""),
            (ChainType::Sui, "\"sui\""),
        ] {
            let json = serde_json::to_string(&chain).unwrap();
            assert_eq!(json, expected);
            let deserialized: ChainType = serde_json::from_str(&json).unwrap();
            assert_eq!(chain, deserialized);
        }
    }

    #[test]
    fn test_namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Cosmos.namespace(), "cosmos");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
        assert_eq!(ChainType::Tron.namespace(), "tron");
        assert_eq!(ChainType::Ton.namespace(), "ton");
        assert_eq!(ChainType::Spark.namespace(), "spark");
        assert_eq!(ChainType::Filecoin.namespace(), "fil");
        assert_eq!(ChainType::Sui.namespace(), "sui");
    }

    #[test]
    fn test_coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Cosmos.default_coin_type(), 118);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
        assert_eq!(ChainType::Tron.default_coin_type(), 195);
        assert_eq!(ChainType::Ton.default_coin_type(), 607);
        assert_eq!(ChainType::Spark.default_coin_type(), 8797555);
        assert_eq!(ChainType::Filecoin.default_coin_type(), 461);
        assert_eq!(ChainType::Sui.default_coin_type(), 784);
    }

    #[test]
    fn test_from_namespace() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("cosmos"), Some(ChainType::Cosmos));
        assert_eq!(
            ChainType::from_namespace("bip122"),
            Some(ChainType::Bitcoin)
        );
        assert_eq!(ChainType::from_namespace("tron"), Some(ChainType::Tron));
        assert_eq!(ChainType::from_namespace("ton"), Some(ChainType::Ton));
        assert_eq!(ChainType::from_namespace("spark"), Some(ChainType::Spark));
        assert_eq!(ChainType::from_namespace("fil"), Some(ChainType::Filecoin));
        assert_eq!(ChainType::from_namespace("sui"), Some(ChainType::Sui));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn test_from_str() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
    }

    #[test]
    fn test_parse_chain_friendly_name() {
        let chain = parse_chain("ethereum").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
        assert_eq!(chain.chain_id, "eip155:1");
    }

    #[test]
    fn test_parse_chain_caip2() {
        let chain = parse_chain("eip155:42161").unwrap();
        assert_eq!(chain.name, "arbitrum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_legacy_evm() {
        let chain = parse_chain("evm").unwrap();
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_type, ChainType::Evm);
    }

    #[test]
    fn test_parse_chain_solana() {
        let chain = parse_chain("solana").unwrap();
        assert_eq!(chain.chain_type, ChainType::Solana);
    }

    #[test]
    fn test_parse_chain_unknown() {
        assert!(parse_chain("unknown_chain").is_err());
    }

    #[test]
    fn test_all_chain_types() {
        assert_eq!(ALL_CHAIN_TYPES.len(), 8);
    }

    #[test]
    fn test_default_chain_for_type() {
        let chain = default_chain_for_type(ChainType::Evm);
        assert_eq!(chain.name, "ethereum");
        assert_eq!(chain.chain_id, "eip155:1");
    }
}
