use crate::CliError;
use ows_pay::{FundProvider, FundRequest, WalletAccountRef};

fn wallet_address_for_chain(wallet_name: &str, chain: &str) -> Result<String, CliError> {
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let parsed = crate::parse_chain(chain)?;

    wallet
        .accounts
        .iter()
        .find(|a| a.chain_id == parsed.chain_id)
        .map(|a| a.address.clone())
        .ok_or_else(|| {
            CliError::InvalidArgs(format!(
                "wallet has no account for chain {} ({})",
                parsed.name, parsed.chain_id
            ))
        })
}

/// `ows fund deposit --provider moonpay --wallet <name> --asset USDC --chain base`
pub fn run(
    provider: &str,
    wallet_name: &str,
    chain: Option<&str>,
    asset: Option<&str>,
) -> Result<(), CliError> {
    let provider: FundProvider = provider.parse().map_err(CliError::InvalidArgs)?;
    let asset = asset.unwrap_or("USDC");
    let wallet = ows_lib::get_wallet(wallet_name, None)?;
    let wallet_accounts: Vec<WalletAccountRef> = wallet
        .accounts
        .iter()
        .map(|account| WalletAccountRef {
            chain_id: account.chain_id.clone(),
            address: account.address.clone(),
        })
        .collect();
    let target = ows_pay::fund::resolve_deposit_target(provider, &wallet_accounts, chain, asset)
        .map_err(|e| CliError::InvalidArgs(e.message))?;

    eprintln!(
        "Creating funding flow with provider \"{provider}\" for wallet \"{wallet_name}\" ({})",
        target.destination_address
    );
    eprintln!("Asset: {}", target.asset);
    eprintln!("Destination chain: {}", target.wallet_chain_name);

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt.block_on(ows_pay::fund::deposit(&FundRequest {
        provider,
        destination_address: target.destination_address,
        asset: target.asset,
        chain: target.chain,
    }))?;

    eprintln!();
    eprintln!(
        "Funding flow created via {} (ID: {})",
        result.provider, result.deposit_id
    );

    if !result.details.is_empty() {
        eprintln!();
        for (key, value) in &result.details {
            eprintln!("{key:>16}: {value}");
        }
    }

    if !result.wallets.is_empty() {
        eprintln!();
        eprintln!("Relevant addresses:");
        for (kind, addr) in &result.wallets {
            eprintln!("  {kind:>10}  {addr}");
        }
    }

    eprintln!();
    eprintln!("{}", result.instructions);
    eprintln!();

    if let Some(url) = &result.action_url {
        println!("{url}");

        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open").arg(url).spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open").arg(url).spawn();
        }
    }

    Ok(())
}

/// `ows fund balance --provider moonpay --wallet <name> --chain base`
pub fn balance(provider: &str, wallet_name: &str, chain: Option<&str>) -> Result<(), CliError> {
    let provider: FundProvider = provider.parse().map_err(CliError::InvalidArgs)?;
    let chain_name = chain.unwrap_or("base");
    let address = wallet_address_for_chain(wallet_name, chain_name)?;

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let balances = rt.block_on(ows_pay::fund::get_balances(
        provider,
        &address,
        Some(chain_name),
    ))?;

    if balances.is_empty() {
        eprintln!("No tokens found for {address} on {chain_name}");
        return Ok(());
    }

    for token in &balances {
        let amount = token.balance.amount;
        let value = token.balance.value;
        println!(
            "{:>12.6} {:6} ${:<10.2}  {}",
            amount, token.symbol, value, token.name
        );
    }

    Ok(())
}

pub fn providers() {
    println!(
        "moonpay  default provider: fiat/hosted deposit flow into wallet tokens on supported EVM chains"
    );
}
