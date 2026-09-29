pub mod bitcoin;
pub mod cardano;
pub mod cosmos;
pub mod evm;
pub mod filecoin;
pub mod midnight;
pub mod nano;
pub mod near;
pub mod solana;
pub mod spark;
pub mod sui;
pub mod ton;
pub mod tron;
pub mod xrpl;

pub use self::bitcoin::BitcoinSigner;
pub use self::cardano::CardanoSigner;
pub use self::cosmos::CosmosSigner;
pub use self::evm::EvmSigner;
pub use self::filecoin::FilecoinSigner;
pub use self::midnight::MidnightSigner;
pub use self::nano::NanoSigner;
pub use self::near::NearSigner;
pub use self::solana::SolanaSigner;
pub use self::spark::SparkSigner;
pub use self::sui::SuiSigner;
pub use self::ton::TonSigner;
pub use self::tron::TronSigner;
pub use self::xrpl::XrplSigner;

use crate::traits::{ChainSigner, SignerError};
use ows_core::{default_chain_for_type, Chain, ChainType};

/// Resolve a signer from a parsed CAIP-2 chain. `parse_chain` accepts any reference
/// within a known namespace, so an unsupported network reaches this point as a
/// `Chain`: `CardanoSigner` reads `chain.chain_id` and rejects a reference it does not
/// know rather than guessing a network — see [`CardanoSigner::from_chain_id`], and
/// [`MidnightSigner::from_chain_id`] reads it the same way. The other families whose
/// address format depends on the network still resolve to one fixed network for every
/// reference in their namespace.
pub fn signer_for_chain(chain: &Chain) -> Result<Box<dyn ChainSigner>, SignerError> {
    Ok(match chain.chain_type {
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
        ChainType::Near => Box::new(NearSigner),
        ChainType::Cardano => Box::new(CardanoSigner::from_chain_id(chain.chain_id)?),
        ChainType::Midnight => Box::new(MidnightSigner::from_chain_id(chain.chain_id)),
    })
}

/// Get a default signer for a given chain family (first registry entry per family).
pub fn signer_for_chain_type(chain_type: ChainType) -> Result<Box<dyn ChainSigner>, SignerError> {
    signer_for_chain(&default_chain_for_type(chain_type))
}
