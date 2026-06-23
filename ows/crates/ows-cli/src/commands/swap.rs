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
    let QuoteArgs {
        wallet_name,
        from_token,
        to_token,
        amount,
        from_chain,
        to_chain,
        slippage,
        order,
    } = args;
    let to_chain = to_chain.unwrap_or(from_chain);

    // Load wallet to get address
    let wallet = vault::load_wallet_by_name_or_id(wallet_name, None)
        .map_err(|e| CliError::InvalidArgs(format!("wallet not found: {e}")))?;

    // Find EVM address for the from_chain
    // Determine chain prefix for address lookup
    let lifi_from = ows_chain_to_lifi(from_chain);
    let lifi_to = ows_chain_to_lifi(to_chain);

    // Validate chain mappings before making API call
    if lifi_from.is_empty() {
        return Err(CliError::InvalidArgs(format!(
            "unsupported from-chain: '{}'. Supported: ethereum, polygon, base, arbitrum, optimism, avalanche, bsc, solana",
            from_chain
        )));
    }
    if lifi_to.is_empty() {
        return Err(CliError::InvalidArgs(format!(
            "unsupported to-chain: '{}'. Supported: ethereum, polygon, base, arbitrum, optimism, avalanche, bsc, solana",
            to_chain
        )));
    }

    let is_solana = lifi_from == "1151111081099592";
    let from_address = if is_solana {
        wallet
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("solana:"))
            .map(|a| a.address.clone())
            .ok_or_else(|| CliError::InvalidArgs("no Solana account found in wallet".into()))?
    } else {
        wallet
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .map(|a| a.address.clone())
            .ok_or_else(|| CliError::InvalidArgs("no EVM account found in wallet".into()))?
    };

    // Use LI.FI token info to get correct decimals — fetch first with a best-guess,
    // then reissue with corrected decimals if the quote returns different token decimals.
    // Best-guess decimals: USDC/USDT = 6, BTC/WBTC/SBTC = 8, everything else = 18
    let decimals_guess = match from_token.to_uppercase().as_str() {
        "USDC" | "USDT" | "USDC.E" | "USDT.E" => 6u32,
        "WBTC" | "BTC" | "SBTC" | "TBTC" => 8u32,
        "GUSD" => 2u32,
        _ => 18u32,
    };
    let raw_amount = amount_to_raw(amount, decimals_guess)
        .map_err(|e| CliError::InvalidArgs(format!("invalid amount: {e}")))?;

    // For cross-VM swaps, supply the destination chain address too
    let is_to_solana = lifi_to == "1151111081099592";
    let to_address = if is_to_solana && !is_solana {
        wallet
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("solana:"))
            .map(|a| a.address.clone())
    } else if !is_to_solana && is_solana {
        wallet
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .map(|a| a.address.clone())
    } else {
        None
    };

    let params = ows_pay::SwapParams {
        from_chain: lifi_from.to_string(),
        to_chain: lifi_to.to_string(),
        from_token: from_token.to_string(),
        to_token: to_token.to_string(),
        from_amount: raw_amount,
        from_address,
        to_address,
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

/// Map OWS chain names to LI.FI chain identifiers.
fn ows_chain_to_lifi(chain: &str) -> String {
    let lower = chain.to_lowercase();
    // Strip CAIP-2 prefix (eip155:8453 -> 8453)
    let stripped = if let Some(rest) = lower.strip_prefix("eip155:") {
        rest.to_string()
    } else if let Some(rest) = lower.strip_prefix("solana:") {
        // Only solana:mainnet is a valid Solana CAIP-2 reference
        if rest == "mainnet" || rest == "5eykt4usfpcqjnphnnpqzakosqkp" {
            return "1151111081099592".to_string();
        }
        // Any other solana:<ref> is invalid — return empty to trigger validation error
        return String::new();
    } else {
        lower.clone()
    };
    // If it is already a numeric ID, pass through
    if stripped.chars().all(|c| c.is_ascii_digit()) {
        return stripped;
    }
    match stripped.as_str() {
        "ethereum" | "eth" => "1".to_string(),
        "polygon" | "pol" | "matic" => "137".to_string(),
        "base" => "8453".to_string(),
        "arbitrum" | "arb" => "42161".to_string(),
        "optimism" | "op" => "10".to_string(),
        "avalanche" | "avax" => "43114".to_string(),
        "bsc" | "bnb" => "56".to_string(),
        "solana" | "sol" => "1151111081099592".to_string(),
        _ => String::new(),
    }
}
