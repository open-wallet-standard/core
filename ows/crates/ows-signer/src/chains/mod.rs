pub mod bitcoin;
pub mod cosmos;
pub mod evm;
pub mod filecoin;
pub mod solana;
pub mod spark;
pub mod stellar;
pub mod sui;
pub mod ton;
pub mod tron;
pub mod xrpl;

pub use self::bitcoin::BitcoinSigner;
pub use self::cosmos::CosmosSigner;
pub use self::evm::EvmSigner;
pub use self::filecoin::FilecoinSigner;
pub use self::solana::SolanaSigner;
pub use self::spark::SparkSigner;
pub use self::stellar::StellarSigner;
pub use self::sui::SuiSigner;
pub use self::ton::TonSigner;
pub use self::tron::TronSigner;
pub use self::xrpl::XrplSigner;

use crate::traits::ChainSigner;
use ows_core::{Chain, ChainType};

/// Get a default signer for a given chain type.
pub fn signer_for_chain(chain: ChainType) -> Box<dyn ChainSigner> {
    signer_for_chain_id(chain, None)
}

/// Get a signer for a specific chain ID when network-specific behavior matters.
pub fn signer_for_chain_info(chain: &Chain) -> Box<dyn ChainSigner> {
    signer_for_chain_id(chain.chain_type, Some(chain.chain_id))
}

fn signer_for_chain_id(chain: ChainType, chain_id: Option<&str>) -> Box<dyn ChainSigner> {
    match chain {
        ChainType::Evm => Box::new(EvmSigner),
        ChainType::Solana => Box::new(SolanaSigner),
        ChainType::Bitcoin => Box::new(BitcoinSigner::mainnet()),
        ChainType::Cosmos => Box::new(CosmosSigner::cosmos_hub()),
        ChainType::Tron => Box::new(TronSigner),
        ChainType::Ton => Box::new(TonSigner),
        ChainType::Spark => Box::new(SparkSigner),
        ChainType::Filecoin => Box::new(FilecoinSigner),
        ChainType::Sui => Box::new(SuiSigner),
        ChainType::Xrpl => Box::new(XrplSigner),
        ChainType::Stellar => match chain_id {
            Some("stellar:testnet") => Box::new(StellarSigner::testnet()),
            _ => Box::new(StellarSigner::mainnet()),
        },
    }
}
