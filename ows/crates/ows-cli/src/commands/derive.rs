use ows_core::{default_chain_for_type, ALL_CHAIN_TYPES};
use ows_signer::{signer_for_chain, HdDeriver, Mnemonic};
use zeroize::Zeroize;

use crate::{parse_chain, CliError};

fn derive_address_for_chain(
    mnemonic: &Mnemonic,
    chain_type: ows_core::ChainType,
    index: u32,
) -> Result<String, CliError> {
    let signer = signer_for_chain(chain_type);

    if signer.needs_raw_seed() {
        let seed = mnemonic.to_seed("");
        Ok(signer.derive_address_from_seed(seed.expose(), index)?)
    } else {
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();
        let key = HdDeriver::derive_from_mnemonic_cached(mnemonic, "", &path, curve)?;
        Ok(signer.derive_address(key.expose())?)
    }
}

pub fn run(chain_str: Option<&str>, index: u32) -> Result<(), CliError> {
    let mut mnemonic_str = super::read_mnemonic()?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    if let Some(cs) = chain_str {
        let chain = parse_chain(cs)?;
        let address = derive_address_for_chain(&mnemonic, chain.chain_type, index)?;
        println!("{address}");
    } else {
        for ct in &ALL_CHAIN_TYPES {
            let chain = default_chain_for_type(*ct);
            let address = derive_address_for_chain(&mnemonic, *ct, index)?;
            println!("{} → {}", chain.chain_id, address);
        }
    }

    Ok(())
}
