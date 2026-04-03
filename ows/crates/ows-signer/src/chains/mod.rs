pub mod bitcoin;
pub mod cosmos;
pub mod evm;
pub mod filecoin;
pub mod nano;
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
pub use self::nano::NanoSigner;
pub use self::solana::SolanaSigner;
pub use self::spark::SparkSigner;
pub use self::stellar::StellarSigner;
pub use self::sui::SuiSigner;
pub use self::ton::TonSigner;
pub use self::tron::TronSigner;
pub use self::xrpl::XrplSigner;

use crate::traits::ChainSigner;
use ows_core::ChainType;

/// Backward-compatible wrapper — dispatches to the default (mainnet) signer for a chain type.
/// Prefer `signer_for_chain(&Chain)` when you have a full Chain with a specific network.
pub fn signer_for_chain_type(chain_type: ChainType) -> Box<dyn ChainSigner> {
    signer_for_chain(&ows_core::default_chain_for_type(chain_type))
}

/// Get a default signer for a given chain.
pub fn signer_for_chain(chain: &ows_core::Chain) -> Box<dyn ChainSigner> {
    match chain.chain_type {
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
        ChainType::Nano => Box::new(NanoSigner),
        ChainType::Stellar => match chain.chain_id {
            "stellar:testnet" => Box::new(StellarSigner::testnet()),
            "stellar:futurenet" => Box::new(StellarSigner::futurenet()),
            _ => Box::new(StellarSigner::pubnet()),
        },
    }
}
