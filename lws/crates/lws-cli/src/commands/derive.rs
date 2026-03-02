use lws_signer::{signer_for_chain, HdDeriver, Mnemonic};
use zeroize::Zeroize;

use crate::{parse_chain, CliError};

pub fn run(chain_str: &str, index: u32) -> Result<(), CliError> {
    let mut mnemonic_str = super::read_mnemonic()?;
    let chain = parse_chain(chain_str)?;
    let mnemonic = Mnemonic::from_phrase(&mnemonic_str)?;
    mnemonic_str.zeroize();

    let signer = signer_for_chain(chain);
    let path = signer.default_derivation_path(index);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
    let address = signer.derive_address(key.expose())?;

    println!("{address}");
    Ok(())
}
