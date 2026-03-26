use crate::error::{PayError, PayErrorCode};
use crate::types::{
    FundProvider, FundRequest, FundResult, MoonPayBalanceRequest, MoonPayBalanceResponse,
    MoonPayDepositRequest, MoonPayDepositResponse, ResolvedFundTarget, TokenBalance,
    WalletAccountRef,
};

const MOONPAY_API: &str = "https://agents.moonpay.com";

/// MoonPay-specific chain mapping. This is separate from the protocol-level
/// CAIP-2 utilities because MoonPay has its own chain name scheme.
/// MoonPay expects the BNB Chain funding slug to be `bnb`, while OWS uses `bsc` as the canonical chain name.
#[derive(Debug)]
struct MoonPayChain {
    wallet_chain_id: &'static str,
    display_name: &'static str,
    moonpay_name: &'static str,
}

const MOONPAY_CHAINS: &[(&str, MoonPayChain)] = &[
    (
        "base",
        MoonPayChain {
            wallet_chain_id: "eip155:8453",
            display_name: "Base",
            moonpay_name: "base",
        },
    ),
    (
        "ethereum",
        MoonPayChain {
            wallet_chain_id: "eip155:1",
            display_name: "Ethereum",
            moonpay_name: "ethereum",
        },
    ),
    (
        "polygon",
        MoonPayChain {
            wallet_chain_id: "eip155:137",
            display_name: "Polygon",
            moonpay_name: "polygon",
        },
    ),
    (
        "arbitrum",
        MoonPayChain {
            wallet_chain_id: "eip155:42161",
            display_name: "Arbitrum",
            moonpay_name: "arbitrum",
        },
    ),
    (
        "optimism",
        MoonPayChain {
            wallet_chain_id: "eip155:10",
            display_name: "Optimism",
            moonpay_name: "optimism",
        },
    ),
    (
        "bsc",
        MoonPayChain {
            wallet_chain_id: "eip155:56",
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "bnb",
        MoonPayChain {
            wallet_chain_id: "eip155:56",
            display_name: "BNB Chain",
            moonpay_name: "bnb",
        },
    ),
    (
        "base-sepolia",
        MoonPayChain {
            wallet_chain_id: "eip155:84532",
            display_name: "Base Sepolia",
            moonpay_name: "base-sepolia",
        },
    ),
    (
        "solana",
        MoonPayChain {
            wallet_chain_id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            display_name: "Solana",
            moonpay_name: "solana",
        },
    ),
];

const DEFAULT_MOONPAY_CHAIN: &MoonPayChain = &MoonPayChain {
    wallet_chain_id: "eip155:8453",
    display_name: "Base",
    moonpay_name: "base",
};

fn resolve_moonpay_chain(chain: Option<&str>) -> Result<&'static MoonPayChain, PayError> {
    match chain {
        Some(name) => {
            let lower = name.to_lowercase();
            MOONPAY_CHAINS
                .iter()
                .find(|(k, _)| *k == lower)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    PayError::new(
                        PayErrorCode::UnsupportedChain,
                        format!("unknown chain for funding: {name}"),
                    )
                })
        }
        None => Ok(DEFAULT_MOONPAY_CHAIN),
    }
}

pub fn resolve_deposit_target(
    provider: FundProvider,
    wallet_accounts: &[WalletAccountRef],
    chain: Option<&str>,
    asset: &str,
) -> Result<ResolvedFundTarget, PayError> {
    match provider {
        FundProvider::MoonPay => resolve_moonpay_target(wallet_accounts, chain, asset),
    }
}

fn resolve_moonpay_target(
    wallet_accounts: &[WalletAccountRef],
    chain: Option<&str>,
    asset: &str,
) -> Result<ResolvedFundTarget, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;
    let account = wallet_accounts
        .iter()
        .find(|account| account.chain_id == mapping.wallet_chain_id)
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::UnsupportedChain,
                format!(
                    "wallet has no account for {} ({})",
                    mapping.display_name, mapping.wallet_chain_id
                ),
            )
        })?;

    Ok(ResolvedFundTarget {
        destination_address: account.address.clone(),
        asset: asset.to_string(),
        chain: Some(mapping.moonpay_name.to_string()),
        wallet_chain_id: mapping.wallet_chain_id.to_string(),
        wallet_chain_name: mapping.display_name.to_string(),
    })
}
/// Create a MoonPay deposit that auto-converts incoming crypto to USDC.
pub async fn deposit(
    request: &FundRequest,
) -> Result<FundResult, PayError> {
    match request.provider {
        FundProvider::MoonPay => {
            moonpay_deposit(&request.destination_address, request.chain.as_deref(), &request.asset)
                .await
        }
    }
}

async fn moonpay_deposit(
    wallet_address: &str,
    chain: Option<&str>,
    token: &str,
) -> Result<FundResult, PayError> {
    let mapping = resolve_moonpay_chain(chain)?;

    let client = reqwest::Client::new();
    let req = MoonPayDepositRequest {
        name: format!("OWS deposit ({token} on {})", mapping.display_name),
        wallet: wallet_address.to_string(),
        chain: mapping.moonpay_name.to_string(),
        token: token.to_string(),
    };

    let resp = client
        .post(format!("{MOONPAY_API}/api/tools/deposit_create"))
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay returned {status}: {body}"),
        ));
    }

    let deposit: MoonPayDepositResponse = resp.json().await?;

    Ok(FundResult {
        provider: FundProvider::MoonPay,
        deposit_id: deposit.id,
        action_url: Some(deposit.deposit_url),
        wallets: deposit
            .wallets
            .iter()
            .map(|w| (w.chain.clone(), w.address.clone()))
            .collect(),
        instructions: deposit.instructions,
        details: vec![
            ("asset".into(), token.to_string()),
            ("chain".into(), mapping.display_name.to_string()),
        ],
    })
}

/// Check token balances for a wallet address via MoonPay.
pub async fn get_balances(
    provider: FundProvider,
    wallet_address: &str,
    chain: Option<&str>,
) -> Result<Vec<TokenBalance>, PayError> {
    if provider != FundProvider::MoonPay {
        return Err(PayError::new(
            PayErrorCode::InvalidInput,
            format!("balance is not supported for provider {}", provider),
        ));
    }

    let mapping = resolve_moonpay_chain(chain)?;
    let client = reqwest::Client::new();

    let req = MoonPayBalanceRequest {
        wallet: wallet_address.to_string(),
        chain: mapping.moonpay_name.to_string(),
    };

    let resp = client
        .post(format!("{MOONPAY_API}/api/tools/token_balance_list"))
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("MoonPay balance returned {status}: {body}"),
        ));
    }

    let balance_resp: MoonPayBalanceResponse = resp.json().await?;
    Ok(balance_resp.items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_bsc_to_bnb() {
        let chain = resolve_moonpay_chain(Some("bsc")).unwrap();
        assert_eq!(chain.display_name, "BNB Chain");
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_bnb_alias() {
        let chain = resolve_moonpay_chain(Some("bnb")).unwrap();
        assert_eq!(chain.display_name, "BNB Chain");
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_chain_is_case_insensitive() {
        let chain = resolve_moonpay_chain(Some("BnB")).unwrap();
        assert_eq!(chain.moonpay_name, "bnb");
    }

    #[test]
    fn resolve_unknown_chain_errors() {
        let err = resolve_moonpay_chain(Some("unknown")).unwrap_err();
        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
    }

    #[test]
    fn resolve_defaults_to_base() {
        let chain = resolve_moonpay_chain(None).unwrap();
        assert_eq!(chain.display_name, "Base");
        assert_eq!(chain.moonpay_name, "base");
        assert_eq!(chain.wallet_chain_id, "eip155:8453");
    }

    fn account(chain_id: &str, address: &str) -> WalletAccountRef {
        WalletAccountRef {
            chain_id: chain_id.to_string(),
            address: address.to_string(),
        }
    }

    #[test]
    fn resolves_moonpay_target_using_provider_mapping() {
        let target = resolve_deposit_target(
            FundProvider::MoonPay,
            &[account("eip155:8453", "0xbase")],
            Some("base"),
            "USDC",
        )
        .unwrap();

        assert_eq!(target.destination_address, "0xbase");
        assert_eq!(target.chain.as_deref(), Some("base"));
        assert_eq!(target.wallet_chain_id, "eip155:8453");
    }

    #[test]
    fn moonpay_target_reports_missing_wallet_account() {
        let err = resolve_deposit_target(
            FundProvider::MoonPay,
            &[account("eip155:1", "0xeth")],
            Some("base"),
            "USDC",
        )
        .unwrap_err();

        assert_eq!(err.code, PayErrorCode::UnsupportedChain);
        assert!(err.message.contains("wallet has no account for Base"));
    }
}
