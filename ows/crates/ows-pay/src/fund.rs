use crate::error::{PayError, PayErrorCode};
use crate::types::{
    FundProvider, FundRequest, FundResult, MoonPayBalanceRequest, MoonPayBalanceResponse,
    MoonPayDepositRequest, MoonPayDepositResponse, NanswapCreateOrderRequest,
    NanswapCreateOrderResponse, NanswapEstimateResponse, ResolvedFundTarget, TokenBalance,
    WalletAccountRef,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use strsim::levenshtein;

const MOONPAY_API: &str = "https://agents.moonpay.com";
const NANSWAP_API: &str = "https://api.nanswap.com/v1";
const PROVIDER_CACHE_TTL_SECS: u64 = 60 * 60;

/// MoonPay-specific chain mapping. This is separate from the protocol-level
/// CAIP-2 utilities because MoonPay has its own chain name scheme.
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
        FundProvider::Nanswap => resolve_nanswap_target(wallet_accounts, chain, asset),
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

fn resolve_nanswap_target(
    wallet_accounts: &[WalletAccountRef],
    chain: Option<&str>,
    asset: &str,
) -> Result<ResolvedFundTarget, PayError> {
    let chain = chain
        .ok_or_else(|| PayError::new(PayErrorCode::InvalidInput, "nanswap requires --chain"))?;

    let chain_lower = chain.to_ascii_lowercase();
    let parsed_chain_id = ows_core::parse_chain(chain)
        .ok()
        .map(|parsed| parsed.chain_id);
    let account = wallet_accounts
        .iter()
        .find(|account| account.chain_id.eq_ignore_ascii_case(chain))
        .or_else(|| {
            parsed_chain_id.and_then(|chain_id| {
                wallet_accounts
                    .iter()
                    .find(|account| account.chain_id == chain_id)
            })
        })
        .or_else(|| {
            if chain_lower == "nano" {
                wallet_accounts
                    .iter()
                    .find(|account| account.chain_id.eq_ignore_ascii_case("nano:mainnet"))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::UnsupportedChain,
                format!("wallet has no account for requested funding target chain: {chain}"),
            )
        })?;

    Ok(ResolvedFundTarget {
        destination_address: account.address.clone(),
        asset: asset.to_string(),
        chain: Some(chain.to_string()),
        wallet_chain_id: account.chain_id.clone(),
        wallet_chain_name: chain.to_string(),
    })
}

/// Create a MoonPay deposit that auto-converts incoming crypto to USDC.
pub async fn deposit(request: &FundRequest) -> Result<FundResult, PayError> {
    match request.provider {
        FundProvider::MoonPay => {
            moonpay_deposit(
                &request.destination_address,
                request.chain.as_deref(),
                &request.asset,
            )
            .await
        }
        FundProvider::Nanswap => {
            nanswap_deposit(
                &request.destination_address,
                &request.asset,
                request.source_asset.as_deref(),
                request.amount,
            )
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

async fn nanswap_deposit(
    destination_address: &str,
    asset: &str,
    source_asset: Option<&str>,
    amount: Option<f64>,
) -> Result<FundResult, PayError> {
    let source_asset = source_asset.ok_or_else(|| {
        PayError::new(
            PayErrorCode::InvalidInput,
            "nanswap requires --source-asset (example: USDC-BASE)",
        )
    })?;
    let amount = amount
        .ok_or_else(|| PayError::new(PayErrorCode::InvalidInput, "nanswap requires --amount"))?;
    let api_key = std::env::var("OWS_NANSWAP_API_KEY").map_err(|_| {
        PayError::new(
            PayErrorCode::InvalidInput,
            "set OWS_NANSWAP_API_KEY to use the nanswap provider",
        )
    })?;

    let client = reqwest::Client::new();
    let source_asset = resolve_nanswap_source_asset(&client, source_asset).await?;
    let estimate: NanswapEstimateResponse = client
        .get(format!("{NANSWAP_API}/get-estimate"))
        .query(&[
            ("from", source_asset.as_str()),
            ("to", asset),
            ("amount", &amount.to_string()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let req = NanswapCreateOrderRequest {
        from: source_asset.clone(),
        to: asset.to_string(),
        amount,
        to_address: destination_address.to_string(),
    };

    let resp = client
        .post(format!("{NANSWAP_API}/create-order"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .header("nanswap-api-key", api_key)
        .json(&req)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            PayErrorCode::HttpStatus,
            format!("Nanswap returned {status}: {body}"),
        ));
    }

    let order: NanswapCreateOrderResponse = resp.json().await?;
    let mut details = vec![
        ("from".into(), order.from.clone()),
        ("to".into(), order.to.clone()),
        (
            "expected_from".into(),
            format!("{:.8}", order.expected_amount_from),
        ),
        (
            "expected_to".into(),
            format!("{:.8}", order.expected_amount_to),
        ),
    ];

    if let Some(speed) = estimate.transaction_speed_forecast {
        details.push(("speed_forecast_seconds".into(), speed));
    }
    if let Some(warning) = estimate.warning_message.filter(|w| !w.is_empty()) {
        details.push(("warning".into(), warning));
    }

    Ok(FundResult {
        provider: FundProvider::Nanswap,
        deposit_id: order.id,
        action_url: order.full_link,
        wallets: vec![
            ("payin".into(), order.payin_address),
            ("payout".into(), order.payout_address),
        ],
        instructions: format!(
            "Send {amount} {source_asset} to the pay-in address to swap into {asset}."
        ),
        details,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NanswapCurrency {
    ticker: String,
    #[serde(default)]
    trading_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderSourceAssetCache {
    fetched_at_unix: u64,
    assets: Vec<String>,
}

async fn resolve_nanswap_source_asset(
    client: &reqwest::Client,
    requested: &str,
) -> Result<String, PayError> {
    let assets = get_nanswap_source_assets(client).await?;
    if let Some(exact) = assets
        .iter()
        .find(|asset| asset.eq_ignore_ascii_case(requested))
    {
        return Ok(exact.clone());
    }

    let suggestions = suggest_assets(requested, &assets);
    let mut message = format!("unsupported nanswap source asset: {requested}");
    if !suggestions.is_empty() {
        message.push_str(". Did you mean ");
        message.push_str(&suggestions.join(", "));
        message.push('?');
    }

    Err(PayError::new(PayErrorCode::InvalidInput, message))
}

async fn get_nanswap_source_assets(client: &reqwest::Client) -> Result<Vec<String>, PayError> {
    if let Some(cached) = load_cached_source_assets(FundProvider::Nanswap)? {
        return Ok(cached);
    }

    let assets = fetch_nanswap_source_assets(client).await?;
    store_cached_source_assets(FundProvider::Nanswap, &assets)?;
    Ok(assets)
}

async fn fetch_nanswap_source_assets(client: &reqwest::Client) -> Result<Vec<String>, PayError> {
    let currencies: HashMap<String, NanswapCurrency> = client
        .get(format!("{NANSWAP_API}/get-currencies"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut assets: Vec<String> = currencies
        .into_iter()
        .filter_map(|(key, currency)| {
            let ticker = if currency.ticker.is_empty() {
                key
            } else {
                currency.ticker
            };
            currency.trading_enabled.then_some(ticker)
        })
        .collect();
    assets.sort();
    assets.dedup();
    Ok(assets)
}

fn load_cached_source_assets(provider: FundProvider) -> Result<Option<Vec<String>>, PayError> {
    let path = provider_cache_path(provider)?;
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(PayError::new(
                PayErrorCode::DiscoveryFailed,
                format!("failed to read provider cache {}: {err}", path.display()),
            ))
        }
    };

    let cache: ProviderSourceAssetCache = serde_json::from_slice(&data)?;
    if now_unix_secs()?.saturating_sub(cache.fetched_at_unix) > PROVIDER_CACHE_TTL_SECS {
        return Ok(None);
    }

    Ok(Some(cache.assets))
}

fn store_cached_source_assets(provider: FundProvider, assets: &[String]) -> Result<(), PayError> {
    let path = provider_cache_path(provider)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            PayError::new(
                PayErrorCode::DiscoveryFailed,
                format!(
                    "failed to create provider cache dir {}: {err}",
                    parent.display()
                ),
            )
        })?;
    }

    let payload = ProviderSourceAssetCache {
        fetched_at_unix: now_unix_secs()?,
        assets: assets.to_vec(),
    };
    let bytes = serde_json::to_vec(&payload)?;
    fs::write(&path, bytes).map_err(|err| {
        PayError::new(
            PayErrorCode::DiscoveryFailed,
            format!("failed to write provider cache {}: {err}", path.display()),
        )
    })
}

fn provider_cache_path(provider: FundProvider) -> Result<PathBuf, PayError> {
    let cache_root = std::env::var_os("OWS_FUND_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(default_cache_root)
        .ok_or_else(|| {
            PayError::new(
                PayErrorCode::DiscoveryFailed,
                "could not determine funding provider cache directory",
            )
        })?;
    Ok(cache_root.join(format!("{}_source_assets.json", provider.as_str())))
}

fn default_cache_root() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".ows").join("cache").join("funding"))
}

fn now_unix_secs() -> Result<u64, PayError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| PayError::new(PayErrorCode::DiscoveryFailed, format!("clock error: {err}")))
}

fn suggest_assets(requested: &str, assets: &[String]) -> Vec<String> {
    let mut scored: Vec<(usize, &String)> = assets
        .iter()
        .map(|asset| (asset_similarity_score(requested, asset), asset))
        .filter(|(score, _)| *score <= 6)
        .collect();
    scored.sort_by(|(left_score, left_asset), (right_score, right_asset)| {
        left_score
            .cmp(right_score)
            .then_with(|| left_asset.len().cmp(&right_asset.len()))
            .then_with(|| left_asset.cmp(right_asset))
    });
    let Some(best_score) = scored.first().map(|(score, _)| *score) else {
        return Vec::new();
    };

    scored
        .into_iter()
        .filter(|(score, _)| *score <= best_score + 1)
        .take(3)
        .map(|(_, asset)| asset.clone())
        .collect()
}

fn asset_similarity_score(left: &str, right: &str) -> usize {
    let left_forms = symbol_forms(left);
    let right_forms = symbol_forms(right);
    left_forms
        .iter()
        .flat_map(|left_form| {
            right_forms
                .iter()
                .map(move |right_form| levenshtein(left_form, right_form))
        })
        .min()
        .unwrap_or(usize::MAX)
}

fn symbol_forms(value: &str) -> Vec<String> {
    let upper = value.trim().to_ascii_uppercase();
    let compact = upper.replace(['-', '_', ' '], "");
    let parts: Vec<&str> = upper
        .split(['-', '_', ' '])
        .filter(|part| !part.is_empty())
        .collect();
    let reversed = if parts.len() > 1 {
        Some(parts.iter().rev().copied().collect::<Vec<_>>().join("-"))
    } else {
        None
    };

    let mut forms = vec![upper, compact];
    if let Some(reversed) = reversed {
        forms.push(reversed.clone());
        forms.push(reversed.replace('-', ""));
    }
    forms.sort();
    forms.dedup();
    forms
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

    #[test]
    fn resolves_nanswap_target_from_exact_chain_id() {
        let target = resolve_deposit_target(
            FundProvider::Nanswap,
            &[account("nano:mainnet", "nano_123")],
            Some("nano:mainnet"),
            "XNO",
        )
        .unwrap();

        assert_eq!(target.destination_address, "nano_123");
        assert_eq!(target.wallet_chain_id, "nano:mainnet");
    }

    #[test]
    fn nanswap_similarity_handles_reversed_market_names() {
        let suggestions = suggest_assets("BSC-BNB", &["BNB-BSC".into(), "USDC-BASE".into()]);
        assert_eq!(suggestions, vec!["BNB-BSC".to_string()]);
    }
}
