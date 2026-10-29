use crate::{audit, CliError};
use ows_core::{parse_chain, ChainType};
use ows_lib::ops::resolve_rpc_url;
use ows_lib::types::AccountInfo;

/// Returns the wallet account matching the target funding chain.
fn find_account_for_chain<'a>(
    accounts: &'a [AccountInfo],
    chain: &str,
) -> Result<&'a AccountInfo, CliError> {
    let parsed_chain =
        parse_chain(chain).map_err(|e| CliError::InvalidArgs(format!("unknown chain: {e}")))?;

    // Prefer the account derived for this exact chain, then the family's: an EVM address is the
    // same on every EVM chain and the stored Midnight address is re-encoded per network, so one
    // account answers for the whole family. No other family falls back: Cardano, Cosmos and Bitcoin
    // encode the network into the address, so another network's account would be the wrong answer.
    let family_shares_account = matches!(
        parsed_chain.chain_type,
        ChainType::Evm | ChainType::Midnight
    );
    let namespace = format!("{}:", parsed_chain.chain_type.namespace());

    accounts
        .iter()
        .find(|a| a.chain_id == parsed_chain.chain_id)
        .or_else(|| {
            family_shares_account
                .then(|| accounts.iter().find(|a| a.chain_id.starts_with(&namespace)))
                .flatten()
        })
        .ok_or_else(|| {
            CliError::InvalidArgs(format!("wallet has no account for chain \"{chain}\""))
        })
}

/// The BIP-44 account a Midnight mnemonic account was derived at, read from its stored path, so the
/// keys unsealed for it match the stored address.
fn account_index(account: &AccountInfo) -> Result<u32, CliError> {
    ows_signer::chains::MidnightSigner::account_from_path(&account.derivation_path).ok_or_else(
        || {
            CliError::InvalidArgs(format!(
                "cannot read the account index from derivation path \"{}\"",
                account.derivation_path
            ))
        },
    )
}

/// Unseal the Midnight account key for a balance read. The passphrase is either an api-key token,
/// which goes through the same policy-enforcing channel as sign-message and sign-transaction and is
/// audited like them, allowed or denied, or the owner passphrase. Without one the empty passphrase is
/// tried, as the signing commands do; when that does not open the wallet there is no credential and
/// only the unshielded balance shows.
fn midnight_credential(
    wallet_name: &str,
    chain: &ows_core::Chain,
    passphrase: Option<&str>,
    index: u32,
) -> Result<Option<ows_signer::SecretBytes>, CliError> {
    match passphrase {
        Some(token) if token.starts_with(ows_lib::key_store::TOKEN_PREFIX) => {
            let (key_file, wallet) =
                ows_lib::key_ops::load_authorized_wallet(token, wallet_name, None)?;
            let wallet_id = wallet.id.clone();
            let unsealed = ows_lib::key_ops::enforce_policies_and_decrypt_key(
                token,
                key_file,
                wallet,
                chain,
                ows_core::PolicyRequestType::ReadBalance,
                None,
                None,
                Some(index),
                None,
            );
            let outcome = match &unsealed {
                Ok(_) => Some(audit::Outcome::Allowed),
                Err(e) => audit::denial(e),
            };
            if let Some(outcome) = outcome {
                audit::log_balance_read(
                    &wallet_id,
                    chain.chain_id,
                    &audit::Actor::ApiKey,
                    &outcome,
                );
            }
            let (key, _) = unsealed?;
            Ok(Some(key))
        }
        Some(passphrase) => Ok(Some(ows_lib::decrypt_signing_key(
            wallet_name,
            ChainType::Midnight,
            passphrase,
            Some(index),
            None,
        )?)),
        None => match ows_lib::decrypt_signing_key(
            wallet_name,
            ChainType::Midnight,
            "",
            Some(index),
            None,
        ) {
            Ok(key) => Ok(Some(key)),
            Err(ows_lib::OwsLibError::Crypto(_)) => {
                eprintln!("note: set OWS_PASSPHRASE to read Midnight shielded/dust balances");
                Ok(None)
            }
            Err(e) => Err(e.into()),
        },
    }
}

/// `ows fund buy --wallet <name> [--chain base] [--token USDC]`
///
/// Creates a MoonPay deposit that generates multi-chain deposit addresses.
/// Anyone can send crypto from any chain — it auto-converts to the target token.
pub fn run(wallet_name: &str, chain: Option<&str>, token: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");

    let account = find_account_for_chain(&wallet.accounts, chain_name)?;
    let address = &account.address;
    let token_name = token.unwrap_or("USDC");

    eprintln!("Creating deposit for wallet \"{wallet_name}\" ({address})");
    eprintln!("Target: {token_name} on {chain_name}");

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::fund::fund(
        address,
        Some(chain_name),
        Some(token_name),
    ))?;

    eprintln!();
    eprintln!("Deposit created (ID: {})", result.deposit_id);
    eprintln!();

    // Show deposit addresses.
    if !result.wallets.is_empty() {
        eprintln!("Send crypto to any of these addresses:");
        for (chain, addr) in &result.wallets {
            eprintln!("  {chain:>10}  {addr}");
        }
        eprintln!();
    }

    eprintln!("{}", result.instructions);
    eprintln!();

    // Print the deposit URL (opens in browser for a web flow).
    println!("{}", result.deposit_url);

    // Try to open in browser.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(&result.deposit_url)
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(&result.deposit_url)
            .spawn();
    }

    Ok(())
}

/// `ows fund balance --wallet <name> [--chain base]`
///
/// Check token balances via MoonPay.
pub fn balance(wallet_name: &str, chain: Option<&str>) -> Result<(), CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let chain_name = chain.unwrap_or("base");

    // Midnight balances come from the Midnight indexer, not MoonPay.
    if let Ok(parsed) = crate::parse_chain(chain_name) {
        if parsed.chain_type == ows_core::ChainType::Midnight {
            let account = find_account_for_chain(&wallet.accounts, chain_name)?;
            let index = account_index(account)?;

            // The passphrase leaves the environment and the unsealed key is dropped as soon as the
            // crypto provider is built, so neither lives through the (long) sync.
            let crypto_provider = {
                let passphrase = crate::commands::take_passphrase();
                midnight_credential(
                    wallet_name,
                    &parsed,
                    passphrase.as_deref().map(String::as_str),
                    index,
                )?
                .map(|credential| {
                    ows_signer::chains::MidnightSigner::from_chain_id(parsed.chain_id)
                        .crypto_provider(&credential)
                })
                .transpose()?
            };

            let config = ows_core::Config::load_or_default();
            return Ok(ows_midnight::print_fund_balance(
                &wallet.id,
                &account.address,
                &parsed,
                Some(config.vault_path.as_path()),
                crypto_provider.as_ref(),
            )?);
        }
    }

    let account = find_account_for_chain(&wallet.accounts, chain_name)?;
    let address = &account.address;

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let chain = parse_chain(chain_name)
        .map_err(|e| CliError::InvalidArgs(format!("unknown chain: {e}")))?;

    let rpc_url = resolve_rpc_url(chain.chain_id, chain.chain_type, None).ok();
    let balances = rt.block_on(ows_pay::fund::get_balances(
        address,
        Some(chain_name),
        rpc_url.as_deref(),
    ))?;

    if balances.is_empty() {
        eprintln!("No tokens found for {address} on {chain_name}");
        return Ok(());
    }

    for token in &balances {
        let amount = token.balance.amount;
        match token.balance.value {
            Some(value) => println!(
                "{:>12.6} {:6} ${:<10.2}  {}",
                amount, token.symbol, value, token.name
            ),
            None => println!("{:>12} {:<10} {}", amount, token.symbol, token.name),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(chain_id: &str, address: &str) -> AccountInfo {
        AccountInfo {
            chain_id: chain_id.to_string(),
            address: address.to_string(),
            derivation_path: String::new(),
        }
    }

    fn address_for<'a>(accounts: &'a [AccountInfo], chain: &str) -> Option<&'a str> {
        find_account_for_chain(accounts, chain)
            .ok()
            .map(|a| a.address.as_str())
    }

    #[test]
    fn evm_and_midnight_fall_back_to_the_family_account() {
        let accounts = [
            account("eip155:1", "0xevm"),
            account("midnight:mainnet", "mn_addr"),
        ];
        assert_eq!(address_for(&accounts, "base"), Some("0xevm"));
        assert_eq!(address_for(&accounts, "midnight:preprod"), Some("mn_addr"));
    }

    #[test]
    fn the_account_index_is_the_hardened_account_segment() {
        let at = |path: &str| AccountInfo {
            derivation_path: path.to_string(),
            ..account("midnight:mainnet", "mn_addr")
        };
        assert_eq!(account_index(&at("m/44'/2400'/0'/0/0")).unwrap(), 0);
        assert_eq!(account_index(&at("m/44'/2400'/7'/0/0")).unwrap(), 7);
        assert!(account_index(&at("")).is_err());
        assert!(account_index(&at("m/44'/2400'/7/0/0")).is_err());
        assert!(account_index(&at("m/44'/2400'/0'/0/7")).is_err());
    }

    #[test]
    fn cardano_never_falls_back_to_another_network() {
        let accounts = [account("cip34:1-764824073", "addr1mainnet")];
        assert_eq!(address_for(&accounts, "cardano"), Some("addr1mainnet"));
        assert_eq!(address_for(&accounts, "cardano-preprod"), None);
    }
}
