use lws_signer::{signer_for_chain, HdDeriver, Mnemonic};

use crate::{parse_chain, CliError};

pub fn run(
    mnemonic_phrase: &str,
    chain_str: &str,
    message: &str,
    index: u32,
) -> Result<(), CliError> {
    let chain = parse_chain(chain_str)?;
    let mnemonic = Mnemonic::from_phrase(mnemonic_phrase)?;
    let signer = signer_for_chain(chain);
    let path = signer.default_derivation_path(index);
    let curve = signer.curve();

    let key = HdDeriver::derive_from_mnemonic_cached(&mnemonic, "", &path, curve)?;
    let output = signer.sign_message(key.expose(), message.as_bytes())?;

    println!("{}", hex::encode(&output.signature));
    Ok(())
}
