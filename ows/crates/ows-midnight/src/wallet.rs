//! Midnight wallet helpers used by the balance-display path: indexer URL and
//! sync-cache scope resolution.

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Config;

use super::cache_io::SyncCacheScope;
use super::wallet_sync::unshielded::UnshieldedUtxo;

fn invalid_input(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::other(msg.into())
}

/// Resolve the configured Midnight indexer URL for a CAIP-2 chain id. A plaintext URL is accepted only
/// for an indexer on this machine, as for the node and the proof server.
pub fn resolve_indexer_url(chain_id: &str) -> Result<String, std::io::Error> {
    let url = Config::load_or_default()
        .rpc_url(chain_id)
        .map(str::to_string)
        .ok_or_else(|| {
            invalid_input(format!(
                "no Midnight indexer URL configured for {chain_id}: set `rpc.{chain_id}` in config \
to an indexer's GraphQL URL (Midnight lists the endpoints for each network at \
https://docs.midnight.network/guides/networks-and-environments)"
            ))
        })?;
    crate::urls::refuse_plaintext_to_remote(&url, "indexer")?;
    Ok(url)
}

/// Resolve an optional Midnight proof-server URL for a CAIP-2 chain id.
///
/// Looks up `rpc["{chain_id}:prover"]` (e.g. `midnight:preview:prover`). Absent or blank means
/// use the in-process local prover — there is no shipped default proof-server endpoint.
pub fn resolve_midnight_prover_url(chain_id: &str) -> Option<String> {
    let key = format!("{chain_id}:prover");
    Config::load_or_default()
        .rpc
        .get(&key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Build a sync-cache scope co-located with the wallet's vault entry.
///
/// The caller has already resolved the wallet id (it loaded the wallet to read
/// its accounts), so the scope is always per-wallet isolated.
pub fn sync_scope_for_wallet(
    wallet_id: &str,
    chain_id: Option<&str>,
    vault_path: Option<&Path>,
) -> SyncCacheScope {
    let mut scope = SyncCacheScope::for_wallet(wallet_id, vault_path);
    if let Some(cid) = chain_id {
        scope = scope.with_chain_id(cid);
    }
    scope
}

/// Sum unshielded UTXO values per token type. The values come from the indexer, so a total that
/// overflows is an error, not a wrapped (release) or panicking (debug) sum.
pub fn sum_utxos_by_token(
    utxos: &[UnshieldedUtxo],
) -> Result<BTreeMap<String, u128>, std::io::Error> {
    let mut totals: BTreeMap<String, u128> = BTreeMap::new();
    for u in utxos {
        let total = totals.entry(u.token_type.clone()).or_insert(0);
        *total = total.checked_add(u.value).ok_or_else(|| {
            invalid_input(format!(
                "unshielded {} balance overflows u128",
                u.token_type
            ))
        })?;
    }
    Ok(totals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utxo(value: u128) -> UnshieldedUtxo {
        UnshieldedUtxo {
            token_type: "00".repeat(32),
            value,
            intent_hash: String::new(),
            output_index: 0,
            owner: String::new(),
            ctime_unix_secs: None,
            registered_for_dust_generation: false,
        }
    }

    #[test]
    fn an_overflowing_unshielded_total_is_an_error() {
        assert!(sum_utxos_by_token(&[utxo(u128::MAX), utxo(2)]).is_err());
        assert_eq!(
            sum_utxos_by_token(&[utxo(u128::MAX - 2), utxo(2)]).unwrap()[&"00".repeat(32)],
            u128::MAX
        );
    }

    #[test]
    fn prover_url_absent_by_default() {
        // Built-in defaults never set `:prover` — local proving is the default.
        assert!(resolve_midnight_prover_url("midnight:preview").is_none());
        assert!(resolve_midnight_prover_url("midnight:mainnet").is_none());
        assert!(resolve_midnight_prover_url("midnight:preprod").is_none());
    }
}
