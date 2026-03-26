use crate::error::{PayError, PayErrorCode};
use crate::types::{
    FundProvider, FundRequest, FundResult, MoonPayBalanceRequest, MoonPayBalanceResponse,
    MoonPayDepositRequest, MoonPayDepositResponse, TokenBalance,
};

const MOONPAY_API: &str = "https://agents.moonpay.com";

/// MoonPay-specific chain mapping. This is separate from the protocol-level
/// CAIP-2 utilities because MoonPay has its own chain name scheme.
struct MoonPayChain {
    display_name: &'static str,
    moonpay_name: &'static str,
}

const MOONPAY_CHAINS: &[(&str, MoonPayChain)] = &[
    (
        "base",
        MoonPayChain {
            display_name: "Base",
            moonpay_name: "base",
        },
    ),
    (
        "ethereum",
        MoonPayChain {
            display_name: "Ethereum",
            moonpay_name: "ethereum",
        },
    ),
    (
        "polygon",
        MoonPayChain {
            display_name: "Polygon",
            moonpay_name: "polygon",
        },
    ),
    (
        "arbitrum",
        MoonPayChain {
            display_name: "Arbitrum",
            moonpay_name: "arbitrum",
        },
    ),
    (
        "optimism",
        MoonPayChain {
            display_name: "Optimism",
            moonpay_name: "optimism",
        },
    ),
    (
        "base-sepolia",
        MoonPayChain {
            display_name: "Base Sepolia",
            moonpay_name: "base-sepolia",
        },
    ),
    (
        "solana",
        MoonPayChain {
            display_name: "Solana",
            moonpay_name: "solana",
        },
    ),
];

const DEFAULT_MOONPAY_CHAIN: &MoonPayChain = &MoonPayChain {
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
