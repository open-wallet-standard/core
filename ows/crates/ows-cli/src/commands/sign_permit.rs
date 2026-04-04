use crate::CliError;
use ows_lib::{sign_permit, types::PermitParams};

pub fn run(
    chain: &str,
    wallet: &str,
    token: &str,
    spender: &str,
    value: &str,
    deadline: u64,
    nonce: Option<u64>,
    rpc_url: Option<&str>,
    index: u32,
    json_output: bool,
) -> Result<(), CliError> {
    let passphrase = super::peek_passphrase();
    let result = sign_permit(
        wallet,
        chain,
        PermitParams {
            token: token.to_string(),
            spender: spender.to_string(),
            value: value.to_string(),
            deadline,
            nonce,
            rpc_url: rpc_url.map(|s| s.to_string()),
        },
        passphrase.as_deref(),
        Some(index),
        None,
    )?;
    if json_output {
        let obj = serde_json::json!({
            "signature": result.signature,
            "v": result.v,
            "r": result.r,
            "s": result.s,
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        println!("{}", result.signature);
    }
    Ok(())
}
