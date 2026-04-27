use crate::CliError;
use ows_lib::vault;

pub struct QuoteArgs<'a> {
    pub wallet_name: &'a str,
    pub from_token: &'a str,
    pub to_token: &'a str,
    pub amount: &'a str,
    pub from_chain: &'a str,
    pub to_chain: Option<&'a str>,
    pub slippage: f64,
    pub order: &'a str,
}

pub fn quote(args: QuoteArgs) -> Result<(), CliError> {
    let QuoteArgs { wallet_name, from_token, to_token, amount, from_chain, to_chain, slippage, order } = args;
    let to_chain = to_chain.unwrap_or(from_chain);

    // Load wallet to get address
    let wallet = vault::load_wallet_by_name_or_id(wallet_name, None)
        .map_err(|e| CliError::InvalidArgs(format!("wallet not found: {e}")))?;

    // Find EVM address for the from_chain
    let from_address = wallet
        .accounts
        .iter()
        .find(|a| a.chain_id.starts_with("eip155:"))
        .map(|a| a.address.clone())
        .ok_or_else(|| CliError::InvalidArgs("no EVM account found in wallet".into()))?;

    // Convert human-readable amount to raw (assume 18 decimals for ETH, 6 for USDC)
    let decimals = if from_token.to_uppercase() == "USDC" || from_token.to_uppercase() == "USDT" {
        6u32
    } else {
        18u32
    };
    let raw_amount = amount_to_raw(amount, decimals)
        .map_err(|e| CliError::InvalidArgs(format!("invalid amount: {e}")))?;

    let params = ows_pay::SwapParams {
        from_chain: from_chain.to_string(),
        to_chain: to_chain.to_string(),
        from_token: from_token.to_string(),
        to_token: to_token.to_string(),
        from_amount: raw_amount,
        from_address,
        slippage,
        order: order.to_string(),
    };

    let rt =
        tokio::runtime::Runtime::new().map_err(|e| CliError::InvalidArgs(format!("tokio: {e}")))?;

    let result = rt
        .block_on(async {
            // Use a dummy wallet for dry-run (no signing needed)
            struct DummyWallet;
            impl ows_pay::WalletAccess for DummyWallet {
                fn supported_chains(&self) -> Vec<ows_core::ChainType> {
                    vec![]
                }
                fn account(&self, _: &str) -> Result<ows_pay::Account, ows_pay::PayError> {
                    Err(ows_pay::PayError::new(
                        ows_pay::PayErrorCode::WalletNotFound,
                        "dry-run",
                    ))
                }
                fn sign_payload(
                    &self,
                    _: &str,
                    _: &str,
                    _: &str,
                ) -> Result<String, ows_pay::PayError> {
                    Err(ows_pay::PayError::new(
                        ows_pay::PayErrorCode::SigningFailed,
                        "dry-run",
                    ))
                }
            }
            ows_pay::swap_dry_run(&DummyWallet, params).await
        })
        .map_err(|e| CliError::InvalidArgs(format!("swap quote failed: {e}")))?;

    // Display result
    eprintln!();
    eprintln!("  Swap Route");
    eprintln!("  ----------");
    eprintln!(
        "  {} {} -> {} {}",
        result.from_amount, result.from_symbol, result.to_amount, result.to_symbol
    );
    eprintln!(
        "  Min received:  {} {}",
        result.to_amount_min, result.to_symbol
    );
    eprintln!("  Via:           {}", result.tool);
    if let Some(gas) = &result.gas_cost_usd {
        eprintln!("  Gas cost:      ~${gas}");
    }
    eprintln!(
        "  Est. time:     {}s",
        result.execution_duration_secs as u64
    );
    eprintln!();
    eprintln!("  [dry-run — no transaction signed]");
    eprintln!();

    Ok(())
}

fn amount_to_raw(amount: &str, decimals: u32) -> Result<String, String> {
    let amount = amount.trim();
    let (int_part, frac_part) = if let Some(dot) = amount.find('.') {
        (&amount[..dot], &amount[dot + 1..])
    } else {
        (amount, "")
    };

    if int_part.is_empty() && frac_part.is_empty() {
        return Err("empty amount".into());
    }

    let frac_trimmed = if frac_part.len() > decimals as usize {
        &frac_part[..decimals as usize]
    } else {
        frac_part
    };

    let frac_padded = format!("{:0<width$}", frac_trimmed, width = decimals as usize);
    let combined = format!("{}{}", int_part.trim_start_matches('0'), frac_padded);
    let trimmed = combined.trim_start_matches('0');
    if trimmed.is_empty() {
        Ok("0".into())
    } else {
        Ok(trimmed.to_string())
    }
}
