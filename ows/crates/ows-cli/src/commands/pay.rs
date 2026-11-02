use crate::commands::read_passphrase;
use crate::CliError;
use ows_core::ChainType;
use ows_lib::nano_rpc::NanoAccountInfo;
use ows_pay::{PayError, PayErrorCode};
use ows_signer::chains::nano::{build_state_block, nano_pubkey_from_address};

/// Concrete WalletAccess backed by ows-lib.
struct OwsLibWallet {
    wallet_name: String,
    passphrase: String,
}

impl ows_pay::WalletAccess for OwsLibWallet {
    fn supported_chains(&self) -> Vec<ChainType> {
        if let Ok(info) = ows_lib::get_wallet(&self.wallet_name, None) {
            let mut chains = Vec::new();
            for acct in &info.accounts {
                let ns = acct.chain_id.split(':').next().unwrap_or("");
                if let Some(ct) = ChainType::from_namespace(ns) {
                    if !chains.contains(&ct) {
                        chains.push(ct);
                    }
                }
            }
            if chains.is_empty() {
                vec![ChainType::Evm]
            } else {
                chains
            }
        } else {
            vec![ChainType::Evm]
        }
    }

    fn account(&self, network: &str) -> Result<ows_pay::Account, ows_pay::PayError> {
        let info = ows_lib::get_wallet(&self.wallet_name, None).map_err(|e| {
            ows_pay::PayError::new(ows_pay::PayErrorCode::WalletNotFound, e.to_string())
        })?;
        let ns = network.split(':').next().unwrap_or("eip155");
        let acct = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with(&format!("{ns}:")))
            .ok_or_else(|| {
                ows_pay::PayError::new(
                    ows_pay::PayErrorCode::WalletNotFound,
                    format!("no {ns} account in wallet"),
                )
            })?;
        Ok(ows_pay::Account {
            address: acct.address.clone(),
        })
    }

    fn sign_payload(
        &self,
        scheme: &str,
        network: &str,
        payload: &str,
    ) -> Result<String, ows_pay::PayError> {
        match scheme {
            "exact" => {
                // EIP-712 typed data signing.
                // ows_lib::sign_typed_data accepts both names ("base") and CAIP-2 IDs.
                let result = ows_lib::sign_typed_data(
                    &self.wallet_name,
                    network,
                    payload,
                    Some(&self.passphrase),
                    None,
                    None,
                    None,
                )
                .map_err(|e| {
                    ows_pay::PayError::new(ows_pay::PayErrorCode::SigningFailed, e.to_string())
                })?;
                Ok(format!("0x{}", result.signature))
            }
            other => Err(ows_pay::PayError::new(
                ows_pay::PayErrorCode::ProtocolUnknown,
                format!("unsupported payment scheme: {other}"),
            )),
        }
    }

    fn send_native(&self, network: &str, to: &str, amount: &str) -> Result<String, PayError> {
        let chain = ows_core::parse_chain(network)
            .map_err(|e| PayError::new(PayErrorCode::UnsupportedChain, e))?;
        if chain.chain_type != ChainType::Nano {
            return Err(PayError::new(
                PayErrorCode::UnsupportedChain,
                format!("native payments are not supported on {network}"),
            ));
        }

        let from = self.account(network)?.address;
        let rpc_url = ows_lib::resolve_rpc_url(chain.chain_id, chain.chain_type, None)
            .map_err(|e| PayError::new(PayErrorCode::InvalidInput, e.to_string()))?;
        let info = ows_lib::nano_rpc::account_info(&rpc_url, &from)
            .map_err(|e| PayError::new(PayErrorCode::HttpTransport, e.to_string()))?
            .ok_or_else(|| {
                PayError::new(
                    PayErrorCode::UnsupportedChain,
                    format!("nano account {from} has no balance (not opened)"),
                )
            })?;

        let block = nano_send_block(&from, &info, to, amount)?;

        let result = ows_lib::sign_and_send(
            &self.wallet_name,
            network,
            &hex::encode(block),
            Some(&self.passphrase),
            None,
            Some(&rpc_url),
            None,
        )
        .map_err(|e| PayError::new(PayErrorCode::SigningFailed, e.to_string()))?;
        Ok(result.tx_hash)
    }
}

/// Build the unsigned 176-byte state block that sends `amount` raw from
/// `from` (whose current state is `info`) to `to`.
fn nano_send_block(
    from: &str,
    info: &NanoAccountInfo,
    to: &str,
    amount: &str,
) -> Result<[u8; 176], PayError> {
    let malformed = |msg: String| PayError::new(PayErrorCode::ProtocolMalformed, msg);
    let invalid = |msg: String| PayError::new(PayErrorCode::InvalidData, msg);

    let account = nano_pubkey_from_address(from)
        .ok_or_else(|| invalid(format!("invalid nano account address: {from}")))?;
    let link = nano_pubkey_from_address(to)
        .ok_or_else(|| malformed(format!("invalid nano payTo: {to}")))?;
    let representative = nano_pubkey_from_address(&info.representative).ok_or_else(|| {
        invalid(format!(
            "invalid representative from RPC: {}",
            info.representative
        ))
    })?;
    let previous: [u8; 32] = hex::decode(&info.frontier)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid(format!("invalid frontier from RPC: {}", info.frontier)))?;
    let balance: u128 = info
        .balance
        .parse()
        .map_err(|_| invalid(format!("invalid balance from RPC: {}", info.balance)))?;
    let amount: u128 = amount
        .parse()
        .ok()
        .filter(|a| *a > 0)
        .ok_or_else(|| malformed(format!("invalid nano amount: {amount:?}")))?;
    let new_balance = balance.checked_sub(amount).ok_or_else(|| {
        PayError::new(
            PayErrorCode::UnsupportedChain,
            format!("insufficient XNO balance: have {balance} raw, need {amount} raw"),
        )
    })?;

    Ok(build_state_block(
        &account,
        &previous,
        &representative,
        new_balance,
        &link,
    ))
}

/// `ows pay request <url> --wallet <name> [--method GET] [--body '{}']`
pub fn run(
    url: &str,
    wallet_name: &str,
    method: &str,
    body: Option<&str>,
    skip_passphrase: bool,
) -> Result<(), CliError> {
    let passphrase = if skip_passphrase {
        String::new()
    } else {
        read_passphrase().to_string()
    };

    let wallet = OwsLibWallet {
        wallet_name: wallet_name.to_string(),
        passphrase,
    };

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::pay(&wallet, url, method, body))?;

    if result.status < 400 {
        if let Some(ref payment) = result.payment {
            if !payment.amount.is_empty() {
                eprintln!(
                    "Paid {} on {} via {}",
                    payment.amount, payment.network, result.protocol
                );
            } else {
                eprintln!("Paid via {}", result.protocol);
            }
        }
    } else {
        if result.payment.is_some() {
            eprintln!("HTTP {} — payment rejected by server", result.status);
        } else {
            eprintln!("HTTP {}", result.status);
        }
    }

    println!("{}", result.body);
    Ok(())
}

/// `ows pay discover [--query <search>] [--limit N] [--offset N]`
pub fn discover(
    query: Option<&str>,
    limit: Option<u64>,
    offset: Option<u64>,
) -> Result<(), CliError> {
    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::discover(query, limit, offset))?;

    if result.services.is_empty() {
        eprintln!("No services found.");
        return Ok(());
    }

    eprintln!(
        "Showing {}-{} of {} services:\n",
        result.offset + 1,
        result.offset + result.services.len() as u64,
        result.total,
    );
    for svc in &result.services {
        println!(
            "  {:>8}  {:<8}  {}",
            svc.price, svc.network, svc.description
        );
        println!("  {:>8}  {:8}  {}", "", "", svc.url);
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ows_signer::chains::nano::nano_address;

    fn info(balance: &str) -> NanoAccountInfo {
        NanoAccountInfo {
            frontier: "11".repeat(32),
            balance: balance.to_string(),
            representative: nano_address(&[3u8; 32]),
        }
    }

    #[test]
    fn nano_send_block_debits_amount_and_links_destination() {
        let from = nano_address(&[1u8; 32]);
        let to = nano_address(&[2u8; 32]);
        let block = nano_send_block(&from, &info("1000"), &to, "250").unwrap();

        let expected = build_state_block(&[1u8; 32], &[0x11; 32], &[3u8; 32], 750, &[2u8; 32]);
        assert_eq!(block, expected);
    }

    #[test]
    fn nano_send_block_insufficient_balance_is_unsupported() {
        let from = nano_address(&[1u8; 32]);
        let to = nano_address(&[2u8; 32]);
        let err = nano_send_block(&from, &info("100"), &to, "250").unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn nano_send_block_rejects_bad_destination_and_amount() {
        let from = nano_address(&[1u8; 32]);
        let to = nano_address(&[2u8; 32]);
        let err = nano_send_block(&from, &info("1000"), "0xabc", "1").unwrap_err();
        assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
        for amount in ["0", "abc", ""] {
            let err = nano_send_block(&from, &info("1000"), &to, amount).unwrap_err();
            assert_eq!(err.code, PayErrorCode::ProtocolMalformed);
        }
    }

    #[test]
    fn send_native_rejects_non_nano_before_touching_wallet() {
        let wallet = OwsLibWallet {
            wallet_name: "does-not-exist".into(),
            passphrase: String::new(),
        };
        let err =
            ows_pay::WalletAccess::send_native(&wallet, "eip155:8453", "0xabc", "1").unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }
}
