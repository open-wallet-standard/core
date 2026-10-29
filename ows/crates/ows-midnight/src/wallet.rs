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

/// The config of the vault an operation runs against: `{vault}/config.json` for a vault the caller
/// named, else the default vault's `~/.ows/config.json`. It names the indexer that feeds coin
/// selection and the proof server that receives spend keys, so it is the vault's own config and never
/// another one found through `$HOME`.
fn vault_config(vault_path: Option<&Path>) -> Config {
    match vault_path {
        Some(vault) => Config::load_or_default_from(&vault.join("config.json")),
        None => Config::load_or_default(),
    }
}

/// Resolve the configured Midnight indexer URL for a CAIP-2 chain id from the vault's config. A
/// plaintext URL is accepted only for an indexer on this machine, as for the node and the proof server.
pub fn resolve_indexer_url(
    chain_id: &str,
    vault_path: Option<&Path>,
) -> Result<String, std::io::Error> {
    let url = vault_config(vault_path)
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

/// Resolve an optional Midnight proof-server URL for a CAIP-2 chain id from the vault's config.
///
/// Looks up `rpc["{chain_id}:prover"]` (e.g. `midnight:preview:prover`). Absent or blank means
/// use the in-process local prover — there is no shipped default proof-server endpoint.
pub fn resolve_midnight_prover_url(chain_id: &str, vault_path: Option<&Path>) -> Option<String> {
    let key = format!("{chain_id}:prover");
    vault_config(vault_path)
        .rpc
        .get(&key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The sync-cache scope of a signing call: its network, with the snapshots and proving keys under the
/// caller's vault (`~/.ows` by default).
pub(crate) fn signing_scope(chain_id: &str, vault_path: Option<&Path>) -> SyncCacheScope {
    SyncCacheScope {
        chain_id: Some(chain_id.to_string()),
        vault_path: vault_path.map(Path::to_path_buf),
        wallet_id: None,
    }
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

    /// A vault directory of its own under the system temp dir, with `config` as its config.json.
    fn vault_with_config(name: &str, config: Option<serde_json::Value>) -> std::path::PathBuf {
        let vault =
            std::env::temp_dir().join(format!("ows-midnight-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&vault);
        std::fs::create_dir_all(&vault).unwrap();
        if let Some(config) = config {
            std::fs::write(vault.join("config.json"), config.to_string()).unwrap();
        }
        vault
    }

    #[test]
    fn prover_url_absent_by_default() {
        // Built-in defaults never set `:prover` — local proving is the default.
        let vault = vault_with_config("no-prover", None);
        for chain_id in ["midnight:preview", "midnight:mainnet", "midnight:preprod"] {
            assert!(resolve_midnight_prover_url(chain_id, Some(&vault)).is_none());
        }
        let _ = std::fs::remove_dir_all(&vault);
    }

    /// A caller that names its vault gets that vault's endpoints and caches: a prover or indexer
    /// configured in `~/.ows` must not reach a signing call made against another vault.
    #[test]
    fn a_named_vault_supplies_the_endpoints_and_the_caches() {
        let vault = vault_with_config(
            "named",
            Some(serde_json::json!({
                "vault_path": "/ignored",
                "rpc": {
                    "midnight:preview": "https://indexer.vault.example/api/v4/graphql",
                    "midnight:preview:prover": "https://prover.vault.example"
                }
            })),
        );
        assert_eq!(
            resolve_indexer_url("midnight:preview", Some(&vault)).unwrap(),
            "https://indexer.vault.example/api/v4/graphql"
        );
        assert_eq!(
            resolve_midnight_prover_url("midnight:preview", Some(&vault)).as_deref(),
            Some("https://prover.vault.example")
        );

        let empty = vault_with_config("empty", None);
        assert!(resolve_midnight_prover_url("midnight:preview", Some(&empty)).is_none());

        let scope = signing_scope("midnight:preview", Some(&vault));
        assert!(crate::cache_io::proving_keys_dir(&scope)
            .unwrap()
            .starts_with(&vault));
        // None only when OWS_MIDNIGHT_SYNC_CACHE turns the snapshots off.
        if let Some(snapshot) =
            crate::cache_io::snapshot_path("dust", "https://indexer.vault.example", "k", &scope)
        {
            assert!(snapshot.starts_with(&vault));
        }

        let _ = std::fs::remove_dir_all(&vault);
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// The indexer a vault names feeds coin selection and learns the wallet's addresses, so a
    /// plaintext URL to another host is refused however it is spelled, without showing its API key.
    #[test]
    fn a_vault_naming_a_plaintext_remote_indexer_is_refused() {
        for (name, url) in [
            (
                "plaintext-http",
                "http://indexer.example/api/v4/graphql?project_id=KEY",
            ),
            (
                "plaintext-ws",
                "ws://10.0.0.5/api/v4/graphql/ws?project_id=KEY",
            ),
        ] {
            let vault = vault_with_config(
                name,
                Some(serde_json::json!({
                    "vault_path": "/ignored",
                    "rpc": { "midnight:preview": url }
                })),
            );
            let err = resolve_indexer_url("midnight:preview", Some(&vault))
                .unwrap_err()
                .to_string();
            let _ = std::fs::remove_dir_all(&vault);
            assert!(err.contains("plaintext"), "{url}: {err}");
            assert!(!err.contains("KEY"), "{url}: {err}");
        }

        let local = "http://127.0.0.1:8088/api/v4/graphql";
        let vault = vault_with_config(
            "plaintext-local",
            Some(serde_json::json!({
                "vault_path": "/ignored",
                "rpc": { "midnight:preview": local }
            })),
        );
        let resolved = resolve_indexer_url("midnight:preview", Some(&vault));
        let _ = std::fs::remove_dir_all(&vault);
        assert_eq!(resolved.unwrap(), local);
    }
}
