use crate::error::PayError;
use crate::wallet::WalletAccess;
use serde::{Deserialize, Serialize};

const LIFI_API: &str = "https://li.quest/v1";

/// LI.FI quote response (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiQuote {
    pub action: LifiAction,
    pub estimate: LifiEstimate,
    pub tool: String,
    #[serde(rename = "toolDetails")]
    pub tool_details: LifiToolDetails,
    #[serde(rename = "transactionRequest")]
    pub transaction_request: Option<LifiTransactionRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiAction {
    #[serde(rename = "fromChainId")]
    pub from_chain_id: u64,
    #[serde(rename = "toChainId")]
    pub to_chain_id: u64,
    #[serde(rename = "fromToken")]
    pub from_token: LifiToken,
    #[serde(rename = "toToken")]
    pub to_token: LifiToken,
    #[serde(rename = "fromAmount")]
    pub from_amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiToken {
    pub symbol: String,
    pub name: String,
    pub decimals: u32,
    pub address: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "logoURI")]
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiEstimate {
    #[serde(rename = "fromAmount")]
    pub from_amount: String,
    #[serde(rename = "toAmount")]
    pub to_amount: String,
    #[serde(rename = "toAmountMin")]
    pub to_amount_min: String,
    #[serde(rename = "executionDuration")]
    pub execution_duration: f64,
    #[serde(rename = "gasCosts")]
    pub gas_costs: Option<Vec<LifiGasCost>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiGasCost {
    pub amount: String,
    #[serde(rename = "amountUSD")]
    pub amount_usd: Option<String>,
    pub token: LifiToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiToolDetails {
    pub name: String,
    #[serde(rename = "logoURI")]
    pub logo_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifiTransactionRequest {
    pub to: String,
    pub data: String,
    pub value: String,
    #[serde(rename = "gasLimit")]
    pub gas_limit: String,
    #[serde(rename = "gasPrice")]
    pub gas_price: Option<String>,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
}

/// Result of a swap quote or execution.
#[derive(Debug, Clone)]
pub struct SwapResult {
    pub from_symbol: String,
    pub to_symbol: String,
    pub from_amount: String,
    pub to_amount: String,
    pub to_amount_min: String,
    pub tool: String,
    pub gas_cost_usd: Option<String>,
    pub execution_duration_secs: f64,
    pub transaction_request: Option<LifiTransactionRequest>,
    pub dry_run: bool,
}

/// Parameters for a swap operation.
pub struct SwapParams {
    pub from_chain: String,
    pub to_chain: String,
    pub from_token: String,
    pub to_token: String,
    pub from_amount: String,
    pub from_address: String,
    pub slippage: f64,
    pub order: String,
}

/// Get a swap/bridge quote from LI.FI.
pub async fn get_quote(params: &SwapParams) -> Result<LifiQuote, PayError> {
    let client = reqwest::Client::new();

    let url = format!(
        "{}/quote?fromChain={}&toChain={}&fromToken={}&toToken={}&fromAmount={}&fromAddress={}&slippage={}&order={}",
        LIFI_API,
        params.from_chain,
        params.to_chain,
        params.from_token,
        params.to_token,
        params.from_amount,
        params.from_address,
        params.slippage,
        params.order,
    );

    let resp = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| PayError::new(crate::error::PayErrorCode::HttpTransport, e.to_string()))?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(PayError::new(
            crate::error::PayErrorCode::HttpStatus,
            format!("LI.FI API error {status}: {body}"),
        ));
    }

    resp.json::<LifiQuote>()
        .await
        .map_err(|e| PayError::new(crate::error::PayErrorCode::ProtocolMalformed, e.to_string()))
}

/// Format token amount with decimals.
pub fn format_amount(raw: &str, decimals: u32) -> String {
    let raw = raw.trim_start_matches('0');
    if raw.is_empty() {
        return "0".to_string();
    }
    let len = raw.len() as u32;
    if len <= decimals {
        let zeros = "0".repeat((decimals - len) as usize);
        let frac = format!("{}{}", zeros, raw);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            "0".to_string()
        } else {
            format!("0.{}", frac)
        }
    } else {
        let (int, frac) = raw.split_at((len - decimals) as usize);
        let frac = frac.trim_end_matches('0');
        if frac.is_empty() {
            int.to_string()
        } else {
            format!("{}.{}", int, frac)
        }
    }
}

/// Execute a dry-run swap (quote only, no signing).
pub async fn swap_dry_run(
    _wallet: &dyn WalletAccess,
    params: SwapParams,
) -> Result<SwapResult, PayError> {
    let quote = get_quote(&params).await?;

    let from_amount_fmt = format_amount(
        &quote.estimate.from_amount,
        quote.action.from_token.decimals,
    );
    let to_amount_fmt = format_amount(&quote.estimate.to_amount, quote.action.to_token.decimals);
    let to_amount_min_fmt = format_amount(
        &quote.estimate.to_amount_min,
        quote.action.to_token.decimals,
    );

    let gas_cost_usd = quote
        .estimate
        .gas_costs
        .as_ref()
        .and_then(|gc| gc.first())
        .and_then(|gc| gc.amount_usd.clone());

    Ok(SwapResult {
        from_symbol: quote.action.from_token.symbol.clone(),
        to_symbol: quote.action.to_token.symbol.clone(),
        from_amount: from_amount_fmt,
        to_amount: to_amount_fmt,
        to_amount_min: to_amount_min_fmt,
        tool: quote.tool_details.name.clone(),
        gas_cost_usd,
        execution_duration_secs: quote.estimate.execution_duration,
        transaction_request: quote.transaction_request.clone(),
        dry_run: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amount_simple() {
        assert_eq!(format_amount("1000000", 6), "1");
        assert_eq!(format_amount("1500000", 6), "1.5");
        assert_eq!(format_amount("100000000000000000", 18), "0.1");
        assert_eq!(format_amount("1000000000000000000", 18), "1");
    }

    #[test]
    fn test_format_amount_zero() {
        assert_eq!(format_amount("0", 6), "0");
        assert_eq!(format_amount("", 6), "0");
    }

    #[test]
    fn test_format_amount_small() {
        assert_eq!(format_amount("1", 6), "0.000001");
    }
}
