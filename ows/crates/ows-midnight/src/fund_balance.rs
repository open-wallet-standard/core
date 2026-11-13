//! `ows fund balance --chain midnight:*` display (unshielded + shielded balances, dust fee status).

use std::collections::BTreeMap;
use std::path::Path;

use ows_core::Chain;
use ows_signer::chains::{MidnightCryptoProvider, MidnightNetwork, MidnightSigner};

use super::tip_verify;
use super::wallet::{resolve_indexer_url, sum_utxos_by_token, sync_scope_for_wallet};
use super::wallet_sync::dust;
use super::{
    block_on, format_dust_specks, get_dust_balance_for_display, get_shielded_balances_for_display,
    get_unshielded_utxos_for_display, parse_token_type, ShieldedBalances, UnshieldedUtxo,
};

/// Print the wallet's Midnight addresses on `chain_id` to stderr: unshielded always, shielded and
/// dust only when the crypto provider is available. They derive from the keys alone, so this needs
/// no indexer and no network.
pub fn print_addresses(
    chain_id: &str,
    unshielded_address: &str,
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<(), std::io::Error> {
    eprintln!(
        "{}",
        addresses_block(chain_id, unshielded_address, crypto_provider)?
    );
    Ok(())
}

fn addresses_block(
    chain_id: &str,
    unshielded_address: &str,
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<String, std::io::Error> {
    let (shielded, dust) = match crypto_provider {
        Some(provider) => {
            let addrs = provider
                .addresses(&MidnightNetwork::from_chain_id(chain_id))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            (addrs.shielded, addrs.dust)
        }
        None => ("(unavailable)".to_string(), "(unavailable)".to_string()),
    };
    Ok(format!(
        "Addresses:\n  Unshielded: {unshielded_address}\n  Shielded:   {shielded}\n  Dust:       {dust}\n"
    ))
}

/// Print one titled section of per-token balances — the amount right-aligned on stdout (so the
/// numbers stay machine-readable) followed by the token type, with the header and any empty note on
/// stderr. The unshielded and shielded sections share this so both render identically; `empty_note`
/// (indented) is shown when the section has no tokens.
fn print_token_balances(header: &str, balances: &BTreeMap<String, u128>, empty_note: &str) {
    eprintln!("{header}");
    if balances.is_empty() {
        eprintln!("  {empty_note}");
    } else {
        for (token_type, amount) in balances {
            println!("{amount:>24} {token_type}");
        }
    }
    eprintln!();
}

/// How the dust ledger is handled for this run, decided before the concurrent sync so the dust
/// replay can join the other streams.
enum DustPlan {
    /// This chain shows no dust-fee section.
    Skip,
    /// Dust section shown, but no crypto provider is available to sync.
    NoProvider,
    /// Sync the dust ledger with the available crypto provider.
    Sync,
}

/// The error a balance read ends with when one of its streams failed after the others printed: the
/// command exits non-zero, so a caller that reads only the exit status never takes the balances it
/// got for all of them.
fn partial_balance(missing: String) -> std::io::Error {
    std::io::Error::other(format!(
        "partial balance: {missing}; the balances printed above are complete"
    ))
}

/// Print DUST fee status: the NIGHT-UTXO registration summary (derived from the public unshielded
/// UTXOs, so always available) and the synced DUST balance when the crypto provider was available.
/// The dust ledger is synced by the caller alongside the other streams; `dust_balance` carries its
/// result. A DUST sync that failed is printed as unavailable and then returned as an error, once the
/// section is complete.
fn print_dust_status(
    unshielded_utxos: &[UnshieldedUtxo],
    dust_plan: &DustPlan,
    dust_balance: Option<Result<(usize, u128), std::io::Error>>,
) -> Result<(), std::io::Error> {
    eprintln!("Dust status (fees):");

    let night_wire = parse_token_type(Some("night"))
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .to_wire_token_type();
    let total_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .count();
    let registered_night = unshielded_utxos
        .iter()
        .filter(|u| u.token_type.eq_ignore_ascii_case(&night_wire))
        .filter(|u| u.registered_for_dust_generation)
        .count();
    let unregistered_night = total_night.saturating_sub(registered_night);

    if total_night == 0 {
        eprintln!("  NIGHT UTXOs: none found (dust generation uses NIGHT inputs)");
    } else {
        eprintln!(
            "  NIGHT UTXOs: total={total_night} registered={registered_night} unregistered={unregistered_night}"
        );
        if unregistered_night > 0 {
            eprintln!(
                "  Fee mode: generationless DUST (can be derived from unregistered NIGHT inputs)"
            );
        } else {
            eprintln!("  Fee mode: DUST spend proofs (all NIGHT inputs already registered)");
        }
    }

    let mut failed = None;
    match dust_plan {
        DustPlan::NoProvider => {
            eprintln!("  DUST seed: unavailable (can't sync dust ledger state)")
        }
        DustPlan::Sync => {
            eprintln!("  DUST seed: available");
            match dust_balance {
                Some(Ok((dust_utxo_count, dust_sum))) => {
                    eprintln!("  DUST UTXOs: {dust_utxo_count}");
                    eprintln!("  DUST balance (specks): {dust_sum}");
                    eprintln!(
                        "  DUST balance: {} (best-effort, wall-clock time)",
                        format_dust_specks(dust_sum)
                    );
                }
                Some(Err(e)) => {
                    eprintln!("  DUST: unavailable ({e})");
                    failed = Some(e);
                }
                None => {}
            }
        }
        DustPlan::Skip => {}
    }
    eprintln!();
    match failed {
        Some(e) => Err(partial_balance(format!(
            "the DUST balance did not sync ({e})"
        ))),
        None => Ok(()),
    }
}

/// Wait for one balance stream's thread, re-raising its panic here if it had one.
fn join_stream<T>(handle: std::thread::ScopedJoinHandle<'_, T>) -> T {
    handle
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// Indexer-backed balance display for `ows fund balance --chain midnight:*`.
///
/// The stored unshielded address is re-encoded for the target network's bech32 HRP and its
/// UTXO set is summed per token. The optional `crypto_provider` (built by the caller from the
/// unsealed account key) additionally derives the shielded/dust addresses; without one they show
/// as unavailable. The addresses print first, before any indexer access.
pub fn print_fund_balance(
    wallet_id: &str,
    stored_unshielded_address: &str,
    chain: &Chain,
    vault_path: Option<&Path>,
    crypto_provider: Option<&MidnightCryptoProvider>,
) -> Result<(), std::io::Error> {
    let chain_id = chain.chain_id;
    let address = MidnightSigner::from_chain_id(chain_id)
        .reencode_unshielded_address(stored_unshielded_address)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    // Shown before the indexer is resolved or synced, so they appear offline, without an indexer
    // configured, and before a first sync that can take minutes.
    print_addresses(chain_id, &address, crypto_provider)?;

    let indexer_url = resolve_indexer_url(chain_id, vault_path)?;
    let sync_scope = sync_scope_for_wallet(wallet_id, Some(chain_id), vault_path);

    // One HTTP block-height read gates the snapshot fast-path for the shielded and dust streams
    // (the unshielded stream resumes its snapshot over the subscription itself, so it doesn't
    // consume it).
    let current_block_height = tip_verify::fetch_current_block_height(&indexer_url);

    // Whether to show and sync the dust-fee section is a runtime property of the network, not its
    // name: probe the indexer's dust ledger and treat dust as applicable only when its stream
    // reports a live tip. A network activates dust automatically here — no code change when a new
    // one (mainnet included) turns it on.
    let dust_liveness = block_on(dust::dust_ledger_liveness(&indexer_url));
    let needs_dust = matches!(dust_liveness, Ok(true));
    let dust_plan = if !needs_dust {
        DustPlan::Skip
    } else if crypto_provider.is_some() {
        DustPlan::Sync
    } else {
        DustPlan::NoProvider
    };
    let dust_chain_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // The three balance streams are independent (separate indexer subscriptions and caches), so
    // sync them concurrently; the wall-clock cost is the slowest stream rather than their sum. Each
    // runs on its own thread, so a long synchronous fold in one stream never leaves another
    // stream's socket unread.
    eprintln!("[ows-midnight] syncing balances from indexer (may take a while on first run)…");
    let (unshielded_res, shielded_res, dust_balance) = std::thread::scope(|threads| {
        let unshielded = threads.spawn(|| {
            block_on(get_unshielded_utxos_for_display(
                &indexer_url,
                &address,
                &sync_scope,
            ))
        });
        let shielded = threads.spawn(|| match crypto_provider {
            Some(provider) => block_on(get_shielded_balances_for_display(
                &indexer_url,
                provider,
                &sync_scope,
                current_block_height,
            )),
            None => Ok(ShieldedBalances::default()),
        });
        let dust = threads.spawn(|| match (&dust_plan, crypto_provider) {
            (DustPlan::Sync, Some(provider)) => Some(block_on(get_dust_balance_for_display(
                &indexer_url,
                provider,
                dust_chain_time,
                &sync_scope,
                current_block_height,
            ))),
            _ => None,
        });
        (
            join_stream(unshielded),
            join_stream(shielded),
            join_stream(dust),
        )
    });

    let unshielded_utxos = unshielded_res.map_err(|e| std::io::Error::other(e.to_string()))?;
    let shielded = shielded_res.map_err(|e| std::io::Error::other(e.to_string()))?;
    let unshielded = sum_utxos_by_token(&unshielded_utxos)?;

    print_token_balances(
        "Unshielded balances:",
        &unshielded,
        &format!("none — no unshielded tokens found for {address} on {chain_id}"),
    );

    // Shielded balances need the crypto provider to sync; without it the section would always read
    // empty, which is misleading, so it is omitted entirely rather than shown as "none".
    if crypto_provider.is_some() {
        print_token_balances(
            "Shielded balances:",
            &shielded,
            "none — no unspent shielded coins found after full sync",
        );
    }

    if needs_dust {
        print_dust_status(&unshielded_utxos, &dust_plan, dust_balance)?;
    }
    if let Err(e) = dust_liveness {
        eprintln!("Dust status (fees):\n  DUST: unavailable ({e})\n");
        return Err(partial_balance(format!(
            "the DUST ledger could not be reached ({e})"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DUST sync that fails ends the read with an error once the section is printed, so the command
    /// exits non-zero; a read with no credential to sync with is not a failure.
    #[test]
    fn a_failed_dust_sync_fails_the_balance_read() {
        let failed = print_dust_status(
            &[],
            &DustPlan::Sync,
            Some(Err(std::io::Error::other("dust stream closed"))),
        )
        .unwrap_err()
        .to_string();
        assert!(failed.starts_with("partial balance:"), "{failed}");
        assert!(failed.contains("dust stream closed"), "{failed}");

        assert!(print_dust_status(&[], &DustPlan::Sync, Some(Ok((2, 5)))).is_ok());
        assert!(print_dust_status(&[], &DustPlan::NoProvider, None).is_ok());
        assert!(print_dust_status(&[], &DustPlan::Skip, None).is_ok());
    }

    /// An indexer the DUST probe cannot reach is told apart from a network with no live DUST ledger,
    /// which `fund balance` reads as complete without a DUST section.
    #[test]
    fn an_unreachable_dust_ledger_is_not_read_as_absent() {
        let probe = block_on(dust::dust_ledger_liveness(
            "http://127.0.0.1:1/api/v4/graphql",
        ));
        assert!(probe.is_err(), "{probe:?}");
    }

    /// A network no config names: the addresses still derive, under its own HRPs.
    #[test]
    fn the_addresses_derive_without_any_indexer() {
        let mut credential = b"MNK1".to_vec();
        credential.extend_from_slice(&[0x11; 96]);
        let provider = MidnightSigner::mainnet()
            .crypto_provider(&ows_signer::SecretBytes::new(credential))
            .unwrap();
        let chain_id = "midnight:no-indexer-here";
        let vault =
            std::env::temp_dir().join(format!("ows-midnight-no-config-{}", std::process::id()));
        assert!(resolve_indexer_url(chain_id, Some(&vault)).is_err());

        let block =
            addresses_block(chain_id, "mn_addr_no-indexer-here1x", Some(&provider)).unwrap();
        assert!(
            block.contains("Unshielded: mn_addr_no-indexer-here1x\n"),
            "{block}"
        );
        assert!(
            block.contains("Shielded:   mn_shield-addr_no-indexer-here1"),
            "{block}"
        );
        assert!(
            block.contains("Dust:       mn_dust_no-indexer-here1"),
            "{block}"
        );

        let keyless = addresses_block(chain_id, "mn_addr_no-indexer-here1x", None).unwrap();
        assert!(keyless.contains("Shielded:   (unavailable)"), "{keyless}");
    }
}
