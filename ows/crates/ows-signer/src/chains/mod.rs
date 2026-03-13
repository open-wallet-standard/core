pub mod bitcoin;
pub mod cosmos;
pub mod evm;
pub mod solana;
pub mod ton;
pub mod tron;

pub use self::bitcoin::BitcoinSigner;
pub use self::cosmos::CosmosSigner;
pub use self::evm::EvmSigner;
pub use self::solana::SolanaSigner;
pub use self::ton::TonSigner;
pub use self::tron::TronSigner;

use crate::traits::ChainSigner;
use ows_core::ChainType;

/// Get a default signer for a given chain type.
pub fn signer_for_chain(chain: ChainType) -> Box<dyn ChainSigner> {
    match chain {
        ChainType::Evm => Box::new(EvmSigner),
        ChainType::Solana => Box::new(SolanaSigner),
        ChainType::Bitcoin => Box::new(BitcoinSigner::mainnet()),
        ChainType::Cosmos => Box::new(CosmosSigner::cosmos_hub()),
        ChainType::Tron => Box::new(TronSigner),
        ChainType::Ton => Box::new(TonSigner),
    }
}
