//! VK-hidden shielded sync: full `zswapLedgerEvents` replay.
//!
//! No viewing key is sent to the indexer. We subscribe to every zswap event, decode each one
//! locally with `tagged_deserialize<Event>`, and fold it into a full `ZswapLocalState` (the
//! commitment Merkle tree + qualified coins) via `replay_events` — the spendable wallet state.
//! Balances are derived from that state; nothing here is signing-specific, every sync builds it.

mod sync_cache;

use futures_util::{SinkExt as _, StreamExt as _};
use midnight_ledger::events::Event;
use midnight_serialize::tagged_deserialize;
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;
use ows_signer::chains::MidnightCryptoProvider;
use serde::Deserialize;
use std::path::Path;
use std::time::{Duration, Instant};

use super::ShieldedWalletState;
use crate::cache_io::{self, SyncCacheScope};
use crate::indexer_ws::{self, IndexerWs};
use crate::midnight_env::{self, SyncStream};

const ZSWAP_LEDGER_SUB: &str = r#"
subscription ZswapLedgerEvents($id: Int) {
  zswapLedgerEvents(id: $id) { id raw maxId protocolVersion }
}
"#;

/// Persist a progress snapshot every N applied events during a long replay, so a later run
/// resumes near the tip even if this one is interrupted.
const ZSWAP_SNAPSHOT_INTERVAL: u64 = 1000;

/// Consecutive connections that advance nothing before a replay gives up. Only a stalled connection
/// counts: a provider that recycles long-lived sockets mid-replay never exhausts the budget.
const ZSWAP_SYNC_MAX_STALLED_ATTEMPTS: u32 = 4;

/// "Nothing synced yet" resume cursor. zswap ledger event ids start at 0, so genesis must sit
/// below 0 to stay distinct from "synced through event 0"; `resume_subscribe_id` clamps it to 0.
const GENESIS_CURSOR: i64 = -1;

/// VK-hidden shielded wallet sync: replay `zswapLedgerEvents` into a full spendable
/// `ZswapLocalState` without ever sending a viewing key to the indexer, persisting it for resume
/// and later spends. Resumes from this zswap key's disk snapshot when present, else from genesis.
pub(super) async fn sync_wallet(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedWalletState, std::io::Error> {
    let seed_fp = hex::encode(
        &crypto_provider
            .shielded_key_fingerprint()
            .map_err(|e| std::io::Error::other(e.to_string()))?[..16],
    );
    let state = run_zswap_replay(
        indexer_url,
        crypto_provider,
        scope,
        &seed_fp,
        current_block_height,
    )
    .await?;
    Ok(ShieldedWalletState {
        zswap: state.wallet,
    })
}

/// Drive the `zswapLedgerEvents` replay into a spendable `ZswapLocalState`, resuming from this
/// key's snapshot when present. Returns the final replay state; the caller projects the wallet
/// (and balances) from it. A snapshot the live events do not fit is discarded and the wallet
/// replayed from genesis.
async fn run_zswap_replay(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    seed_fp: &str,
    current_block_height: Option<i64>,
) -> Result<ZswapReplayState, std::io::Error> {
    let replay = |allow_resume| {
        replay_zswap(
            indexer_url,
            crypto_provider,
            scope,
            seed_fp,
            current_block_height,
            allow_resume,
        )
    };
    match replay(true).await {
        Err(e) if crate::tip_verify::is_stale_snapshot(&e) => {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: the live events do not fit the snapshot ({e}); \
discarding it and replaying from genesis"
            );
            replay(false).await
        }
        result => result,
    }
}

/// One replay attempt behind [`run_zswap_replay`]: from this key's snapshot when `allow_resume`
/// and one is usable, else from genesis.
async fn replay_zswap(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    seed_fp: &str,
    current_block_height: Option<i64>,
    allow_resume: bool,
) -> Result<ZswapReplayState, std::io::Error> {
    let fp = cache_io::sync_site_fingerprint(indexer_url, scope);
    let cache_path = sync_cache::snapshot_path(indexer_url, seed_fp, scope);
    let live_genesis = if cache_path.is_some() {
        crate::tip_verify::fetch_genesis_hash(indexer_url).await
    } else {
        None
    };

    let mut wallet = ZswapLocalState::new();
    let mut last_seen_id: i64 = GENESIS_CURSOR;
    let mut max_id: Option<i64> = None;
    let mut saved_block_height: i64 = 0;
    let mut genesis_hash = live_genesis.clone().unwrap_or_default();

    // Resume only from a snapshot for this same indexer site, network, and zswap key.
    let resumed = cache_path
        .as_ref()
        .filter(|_| allow_resume)
        .and_then(|p| sync_cache::try_load_snapshot(p))
        .filter(|snap| {
            cache_io::snapshot_site_matches(scope, &snap.chain_id, &fp, &snap.indexer_fingerprint)
                && snap.zswap_key_fingerprint == seed_fp
        })
        .filter(|snap| {
            let foreign = crate::tip_verify::snapshot_from_other_chain(
                &snap.genesis_hash,
                live_genesis.as_deref(),
            );
            if foreign {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents: snapshot's genesis hash does not match the \
live chain; discarding it and replaying from genesis"
                );
            }
            !foreign
        })
        .and_then(|snap| {
            let w = super::cache::decode_zswap_state(&snap.zswap_state_hex).ok()?;
            Some((
                w,
                snap.last_seen_event_id,
                snap.max_id_when_saved,
                snap.block_height_when_saved,
                snap.genesis_hash,
            ))
        });
    // Live stream tip observed while validating a resume snapshot (None from genesis or an
    // inconclusive probe). Used both to reject a stale snapshot and to skip the WebSocket
    // catch-up when the snapshot already sits at the tip.
    let mut live_tip: Option<i64> = None;
    let mut from_snapshot = false;
    if let Some((resumed_wallet, last, saved_max, saved_height, saved_genesis)) = resumed {
        // Validate the snapshot's cursor against the live stream tip before trusting it. A cursor
        // past the tip means an indexer/chain reset rewound the event ledger; resuming from it
        // would subscribe past the tip and report the defunct chain's phantom balances. Probe only
        // here (we have a snapshot to validate); an undetermined tip keeps the snapshot (fail-safe).
        live_tip = match indexer_ws::probe_stream_max_id(indexer_url, ZSWAP_LEDGER_SUB).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "[ows-midnight] zswapLedgerEvents: tip probe failed ({e}); keeping snapshot"
                );
                None
            }
        };
        if crate::tip_verify::snapshot_stale_by_event_tip(last, live_tip) {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: snapshot tip {last} is past the live tip {}; \
discarding stale snapshot and replaying from genesis",
                live_tip.unwrap_or(-1)
            );
        } else {
            wallet = resumed_wallet;
            from_snapshot = true;
            last_seen_id = last;
            max_id = Some(saved_max);
            saved_block_height = saved_height;
            if genesis_hash.is_empty() {
                genesis_hash = saved_genesis;
            }
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: resuming spend wallet from snapshot (event id {}, saved tip {saved_max})",
                resume_subscribe_id(last_seen_id)
            );
        }
    } else {
        eprintln!("[ows-midnight] zswapLedgerEvents: replaying from genesis");
    }

    let mut state = ZswapReplayState {
        wallet,
        from_snapshot,
        last_seen_id,
        max_id,
        n_events: 0,
        last_event_at: None,
    };

    // Event-tip fast path: the resume probe already learned the live stream tip. When the snapshot
    // sits at it, the on-disk state is current — return it without a WebSocket catch-up, which
    // would otherwise idle-wait a full window for a boundary frame that never comes once the block
    // advanced but no new ledger events did. More reliable than the HTTP height check below, which
    // misses whenever the block advanced with no zswap events.
    if live_tip.is_some_and(|m| m > 0 && state.last_seen_id >= m) {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: snapshot already at live tip {}; using on-disk snapshot",
            state.last_seen_id
        );
        return Ok(state);
    }

    // HTTP-tip fallback, used only when the event-tip probe above was inconclusive (`live_tip`
    // is `None`): when the indexer's block height still matches the snapshot's, skip the WebSocket
    // catch-up. With a known `live_tip` the event-tip fast path already decided, so this must not
    // fire — otherwise a height that held steady while ledger events advanced would return a stale
    // wallet.
    let snapshot_complete = state
        .max_id
        .is_some_and(|m| m > 0 && state.last_seen_id >= m);
    if crate::tip_verify::snapshot_fresh_by_http_tip(
        current_block_height,
        saved_block_height,
        snapshot_complete,
        live_tip,
    ) {
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: indexer block height unchanged ({saved_block_height}); using on-disk snapshot"
        );
        return Ok(state);
    }

    let cfg = ZswapReplayCfg {
        ws_idle: midnight_env::ws_idle_timeout(SyncStream::Shielded),
        stall_timeout: midnight_env::stall_timeout(SyncStream::Shielded),
        progress_interval: 1000,
        sync_started: Instant::now(),
    };
    let cache = cache_path.as_deref().map(|path| ZswapCache {
        path,
        scope,
        fp: &fp,
        key_fp: seed_fp,
        block_height: current_block_height.unwrap_or(0),
        genesis_hash: &genesis_hash,
    });

    let mut stalled_attempts = 0u32;
    for attempt in 0u32.. {
        if attempt > 0 {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: reconnecting (attempt {}) from event id {}",
                attempt + 1,
                resume_subscribe_id(state.last_seen_id)
            );
        }
        let cursor_before = state.last_seen_id;

        eprintln!("[ows-midnight] zswapLedgerEvents: connecting to indexer websocket…");

        let mut ws =
            indexer_ws::connect_and_init(indexer_url, cfg.ws_idle, Some("zswapLedgerEvents"))
                .await?;

        let resume_id = resume_subscribe_id(state.last_seen_id);
        eprintln!(
            "[ows-midnight] zswapLedgerEvents: subscribed from event id {resume_id} (last_seen_id={})",
            state.last_seen_id
        );
        indexer_ws::subscribe(
            &mut ws,
            "1",
            ZSWAP_LEDGER_SUB,
            serde_json::json!({ "id": resume_id }),
        )
        .await?;

        let (dropped, attempt_events) =
            replay_zswap_ws_loop(&mut ws, crypto_provider, &mut state, &cfg, cache.as_ref())
                .await?;

        drop(ws);

        if dropped {
            save_zswap_snapshot(cache.as_ref(), &state);
        }
        if !dropped && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
            eprintln!(
                "[ows-midnight] zswapLedgerEvents: caught up (last_seen_id={} max_id={})",
                state.last_seen_id,
                state.max_id.unwrap_or(-1)
            );
            break;
        }
        // Progress is the cursor advancing, not events arriving: a resume may re-send the event at
        // the cursor.
        if state.last_seen_id > cursor_before {
            stalled_attempts = 0;
        } else {
            stalled_attempts += 1;
        }
        if stalled_attempts < ZSWAP_SYNC_MAX_STALLED_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(
                250u64.saturating_mul(u64::from(stalled_attempts + 1)),
            ))
            .await;
            continue;
        }
        if attempt_events == 0 && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
            break;
        }
        save_zswap_snapshot(cache.as_ref(), &state);
        return Err(std::io::Error::other(format!(
            "zswap ledger sync incomplete: last_seen_id={} max_id={:?}; try again",
            state.last_seen_id, state.max_id
        )));
    }

    save_zswap_snapshot(cache.as_ref(), &state);

    eprintln!(
        "[ows-midnight] zswapLedgerEvents replay done: events_seen={} last_seen_id={} max_id={:?}",
        state.n_events, state.last_seen_id, state.max_id
    );

    Ok(state)
}

struct ZswapReplayState {
    /// Full spendable state (Merkle tree + qualified coins), built on every sync; the snapshot
    /// persists it and the balance is derived from it.
    wallet: ZswapLocalState<InMemoryDB>,
    /// Whether `wallet` started from a disk snapshot, so a fold failure proves the snapshot stale.
    from_snapshot: bool,
    /// Highest event id folded into `wallet` — the wallet holds exactly the events up to it, so it
    /// is both the resume cursor and the fold gate.
    last_seen_id: i64,
    max_id: Option<i64>,
    n_events: u64,
    last_event_at: Option<Instant>,
}

struct ZswapReplayCfg {
    ws_idle: Duration,
    stall_timeout: Duration,
    progress_interval: u64,
    sync_started: Instant,
}

/// Where to persist the zswap replay snapshot, plus the keys that scope it.
struct ZswapCache<'a> {
    path: &'a Path,
    scope: &'a SyncCacheScope,
    fp: &'a str,
    key_fp: &'a str,
    /// Indexer HTTP tip height observed at sync start; stamped onto saved snapshots so a
    /// later run can skip the WebSocket catch-up when the tip is unchanged.
    block_height: i64,
    /// Genesis hash of the chain being synced (empty when unknown); stamped onto saved snapshots.
    genesis_hash: &'a str,
}

/// Persist the spendable wallet state + cursor for the next run (best-effort; ignored when caching
/// is disabled or serialization fails). The freshly built wallet is always current, so it is
/// persisted directly — no stale-tree preservation dance.
fn save_zswap_snapshot(cache: Option<&ZswapCache<'_>>, state: &ZswapReplayState) {
    let Some(cache) = cache else {
        return;
    };
    let Ok(zswap_state_hex) = super::cache::encode_zswap_state(&state.wallet) else {
        return;
    };
    cache_io::try_save(
        cache.path,
        &sync_cache::ShieldedSyncSnapshot {
            version: sync_cache::SNAPSHOT_VERSION,
            indexer_fingerprint: cache.fp.to_string(),
            chain_id: cache_io::snapshot_chain_id(cache.scope),
            zswap_key_fingerprint: cache.key_fp.to_string(),
            last_seen_event_id: state.last_seen_id,
            max_id_when_saved: state
                .max_id
                .map(|m| m.max(state.last_seen_id))
                .unwrap_or(state.last_seen_id),
            block_height_when_saved: cache.block_height,
            genesis_hash: cache.genesis_hash.to_string(),
            zswap_state_hex,
        },
    );
}

/// Subscribe id for resuming the zswap ledger subscription. The indexer treats `id` as an
/// inclusive lower bound, so resuming from the last-seen event re-sends that event —
/// carrying the live max id — instead of tailing silently past the tip when nothing new has
/// happened. The unshielded sync resumes the same way. Genesis (no cursor) starts at 0.
fn resume_subscribe_id(last_seen_id: i64) -> i64 {
    last_seen_id.max(0)
}

/// Decode one raw zswap ledger event and fold it into the spendable `ZswapLocalState` via
/// `crypto_provider.fold_shielded` — adding owned output commitments to the Merkle tree and
/// removing spent inputs. This is the single source for both the balance (summed from the
/// wallet's coins) and spends.
fn fold_zswap_event(
    crypto_provider: &MidnightCryptoProvider,
    wallet: &mut ZswapLocalState<InMemoryDB>,
    raw: &str,
    from_snapshot: bool,
) -> Result<(), std::io::Error> {
    let raw_hex = raw.strip_prefix("0x").unwrap_or(raw);
    let bytes = hex::decode(raw_hex)
        .map_err(|e| std::io::Error::other(format!("invalid zswap event raw hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    let ev: Event<InMemoryDB> = tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("decode zswap event: {e}")))?;
    *wallet = crypto_provider
        .fold_shielded(wallet.clone(), &ev)
        .map_err(|e| {
            crate::tip_verify::fold_failure(
                from_snapshot,
                std::io::Error::other(format!("replay zswap event into wallet: {e}")),
            )
        })?;
    Ok(())
}

/// Drain zswap-ledger events from `ws`, folding each into `state.wallet` until the tip is
/// reached or the socket drops. Transport only; per-event folding lives in [`fold_zswap_event`].
/// Returns `(dropped, events_seen_this_attempt)`.
async fn replay_zswap_ws_loop(
    ws: &mut IndexerWs,
    crypto_provider: &MidnightCryptoProvider,
    state: &mut ZswapReplayState,
    cfg: &ZswapReplayCfg,
    cache: Option<&ZswapCache<'_>>,
) -> Result<(bool, u64), std::io::Error> {
    use tokio_tungstenite::tungstenite::Message;

    let mut dropped = false;
    let mut attempt_events: u64 = 0;

    loop {
        let stall_elapsed = state.last_event_at.unwrap_or(cfg.sync_started).elapsed();
        if stall_elapsed > cfg.stall_timeout {
            save_zswap_snapshot(cache, state);
            return Err(std::io::Error::other(format!(
                "no zswap ledger events for {}s (last_seen_id={} max_id={:?}); \
indexer may be stalled",
                cfg.stall_timeout.as_secs(),
                state.last_seen_id,
                state.max_id
            )));
        }

        let msg = match tokio::time::timeout(cfg.ws_idle, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(_))) | Ok(None) => {
                dropped = true;
                break;
            }
            Err(_) => {
                if attempt_events == 0 && state.max_id.is_some_and(|m| state.last_seen_id >= m) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: no new events (already at tip last_seen_id={} max_id={:?})",
                        state.last_seen_id, state.max_id
                    );
                    dropped = false;
                } else {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents: no indexer message for {}s (last_seen_id={} max_id={:?})",
                        cfg.ws_idle.as_secs(),
                        state.last_seen_id,
                        state.max_id
                    );
                    dropped = true;
                }
                break;
            }
        };

        let Message::Text(t) = msg else {
            match msg {
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                }
                Message::Pong(_) | Message::Binary(_) | Message::Frame(_) => {}
                Message::Close(_) => {
                    dropped = true;
                }
                Message::Text(_) => unreachable!(),
            }
            if dropped {
                break;
            }
            continue;
        };
        state.last_event_at = Some(Instant::now());

        let frame: indexer_ws::WsFrame<ZswapWsData> =
            serde_json::from_str(&t).map_err(|e| std::io::Error::other(e.to_string()))?;
        match frame.r#type.as_str() {
            "next" => {
                let Some(payload) = frame.payload else {
                    continue;
                };
                if let Some(errs) = payload.errors.as_ref() {
                    let msg = errs
                        .first()
                        .and_then(|e| e.get("message").and_then(|m| m.as_str()))
                        .unwrap_or("unknown GraphQL error");
                    return Err(std::io::Error::other(format!(
                        "indexer GraphQL error: {msg}"
                    )));
                }
                let Some(zdata) = payload.data else {
                    continue;
                };
                let Some(evt) = zdata.zswap_ledger_events else {
                    continue;
                };
                state.max_id = Some(match state.max_id {
                    Some(m) => m.max(evt.max_id),
                    None => evt.max_id,
                });
                state.n_events = state.n_events.saturating_add(1);
                attempt_events = attempt_events.saturating_add(1);

                // Every subscription — the first one and each reconnect — resumes inclusively, so
                // the indexer re-sends the event at the cursor. It is already in the wallet, and
                // `replay_events` rejects re-inserting a committed output, so fold only past it.
                if evt.id > state.last_seen_id {
                    fold_zswap_event(
                        crypto_provider,
                        &mut state.wallet,
                        &evt.raw,
                        state.from_snapshot,
                    )?;
                    state.last_seen_id = evt.id;
                }

                if state.n_events == 1 || state.n_events.is_multiple_of(cfg.progress_interval) {
                    eprintln!(
                        "[ows-midnight] zswapLedgerEvents replay progress: last_seen_id={} max_id={:?} events_seen={}",
                        state.last_seen_id, state.max_id, state.n_events
                    );
                }
                if state.n_events.is_multiple_of(ZSWAP_SNAPSHOT_INTERVAL) {
                    save_zswap_snapshot(cache, state);
                }

                if state.max_id.is_some_and(|m| state.last_seen_id >= m) {
                    dropped = false;
                    break;
                }
            }
            "complete" => {
                dropped = false;
                break;
            }
            _ => {}
        }
    }

    Ok((dropped, attempt_events))
}

#[derive(Debug, Default, Deserialize)]
struct ZswapWsData {
    #[serde(rename = "zswapLedgerEvents")]
    #[serde(default)]
    zswap_ledger_events: Option<ZswapLedgerEventWire>,
}

#[derive(Debug, Deserialize)]
struct ZswapLedgerEventWire {
    id: i64,
    raw: String,
    #[serde(rename = "maxId")]
    max_id: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_indexer::{self, MockEvent};
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::Commitment;
    use midnight_ledger::events::{EventDetails, EventSource, ZswapPreimageEvidence};
    use midnight_ledger::structure::TransactionHash;
    use midnight_serialize::tagged_serialize;
    use ows_signer::chains::MidnightSigner;
    use ows_signer::SecretBytes;

    fn provider() -> MidnightCryptoProvider {
        let mut blob = b"MNK1".to_vec();
        blob.extend_from_slice(&[0x11; 32]);
        blob.extend_from_slice(&[0x22; 32]);
        blob.extend_from_slice(&[0x33; 32]);
        MidnightSigner::mainnet()
            .crypto_provider(&SecretBytes::new(blob))
            .expect("provider")
    }

    /// A zswap ledger event committing someone else's output at `mt_index`: the wallet inserts it
    /// into its commitment tree, which accepts only the next free index.
    fn foreign_output(mt_index: u64) -> MockEvent {
        foreign_output_at(mt_index as i64, mt_index)
    }

    /// [`foreign_output`] carried by the stream event `id`, which a reset chain no longer keeps in
    /// step with the tree index.
    fn foreign_output_at(id: i64, mt_index: u64) -> MockEvent {
        let event = Event::<InMemoryDB> {
            source: EventSource {
                transaction_hash: TransactionHash(HashOutput([0; 32])),
                logical_segment: 0,
                physical_segment: 0,
            },
            content: EventDetails::ZswapOutput {
                commitment: Commitment(HashOutput([mt_index as u8 + 1; 32])),
                preimage_evidence: ZswapPreimageEvidence::None,
                contract: None,
                mt_index,
            },
        };
        let mut raw = Vec::new();
        tagged_serialize(&event, &mut raw).expect("serialize event");
        MockEvent {
            id,
            raw: hex::encode(raw),
        }
    }

    /// A connection that drops mid-replay reconnects from the last event folded, and the indexer
    /// re-sends that event. It is already in the wallet, so folding it again would fail the
    /// commitment tree's linear insertion and abort the whole balance run.
    #[tokio::test]
    async fn a_reconnect_does_not_fold_the_re_sent_boundary_event_twice() {
        let url = mock_indexer::spawn(
            "zswapLedgerEvents",
            (0..6).map(foreign_output).collect(),
            Some(3),
        )
        .await;
        let vault = std::env::temp_dir().join(format!(
            "ows-midnight-zswap-reconnect-{}",
            std::process::id()
        ));
        let scope = SyncCacheScope::for_wallet("w", Some(&vault));

        let state = run_zswap_replay(&url, &provider(), &scope, "fp", None).await;
        let _ = std::fs::remove_dir_all(&vault);

        let state = state.expect("the reconnect must resume the replay");
        assert_eq!(state.last_seen_id, 5);
        assert_eq!(state.wallet.first_free, 6);
    }

    /// A provider that recycles connections drops a long replay many times, each connection still
    /// advancing it. Only connections that advance nothing count against the retry budget, so the
    /// replay runs to the tip however many times its socket is recycled.
    #[tokio::test]
    async fn a_provider_that_recycles_connections_never_exhausts_the_retry_budget() {
        let url = mock_indexer::spawn(
            "zswapLedgerEvents",
            (0..20).map(foreign_output).collect(),
            Some(3),
        )
        .await;
        let vault = std::env::temp_dir().join(format!(
            "ows-midnight-zswap-recycled-{}",
            std::process::id()
        ));
        let scope = SyncCacheScope::for_wallet("w", Some(&vault));

        let state = run_zswap_replay(&url, &provider(), &scope, "fp", None).await;
        let _ = std::fs::remove_dir_all(&vault);

        let state = state.expect("a replay advancing on every connection must finish");
        assert_eq!(state.last_seen_id, 19);
        assert_eq!(state.wallet.first_free, 20);
    }

    /// A snapshot the live stream does not fit — here a reset chain the genesis check could not
    /// catch, because the genesis query failed — makes the resumed fold fail. The snapshot is then
    /// discarded and the wallet replayed from genesis, rather than failing every run until the
    /// cache is deleted by hand.
    #[tokio::test]
    async fn a_snapshot_the_live_events_do_not_fit_is_replayed_from_genesis() {
        // The reset chain: its first output sits at event id 4, so ids no longer match tree indexes.
        let url = mock_indexer::spawn(
            "zswapLedgerEvents",
            (4..9)
                .map(|id| foreign_output_at(id, id as u64 - 4))
                .collect(),
            None,
        )
        .await;
        let vault =
            std::env::temp_dir().join(format!("ows-midnight-zswap-stale-{}", std::process::id()));
        let scope = SyncCacheScope::for_wallet("w", Some(&vault));

        // The old chain's snapshot: six outputs folded, cursor at event 5, no genesis hash.
        let provider = provider();
        let mut wallet = ZswapLocalState::new();
        for e in (0..6).map(foreign_output) {
            fold_zswap_event(&provider, &mut wallet, &e.raw, false).expect("fold");
        }
        let fp = cache_io::sync_site_fingerprint(&url, &scope);
        let path = sync_cache::snapshot_path(&url, "fp", &scope).expect("cache path");
        let cache = ZswapCache {
            path: &path,
            scope: &scope,
            fp: &fp,
            key_fp: "fp",
            block_height: 0,
            genesis_hash: "",
        };
        let stale = ZswapReplayState {
            wallet,
            from_snapshot: false,
            last_seen_id: 5,
            max_id: Some(5),
            n_events: 0,
            last_event_at: None,
        };
        save_zswap_snapshot(Some(&cache), &stale);

        let state = run_zswap_replay(&url, &provider, &scope, "fp", None).await;
        let _ = std::fs::remove_dir_all(&vault);

        let state = state.expect("a stale snapshot must fall back to a genesis replay");
        assert!(!state.from_snapshot);
        assert_eq!(state.last_seen_id, 8);
        assert_eq!(state.wallet.first_free, 5);
    }

    /// An indexer that keeps dropping the connection fails the signing path's shielded sync rather
    /// than hand back a partial wallet, and keeps the progress made. Once the indexer is back, the
    /// next sync resumes from that snapshot and builds the wallet a clean replay builds.
    #[tokio::test]
    async fn a_sync_cut_short_by_an_outage_recovers_once_the_indexer_is_back() {
        let events = || (0..6).map(foreign_output);
        let (url, cut) =
            mock_indexer::spawn_with_cut("zswapLedgerEvents", events().collect(), Some(1)).await;
        let vault =
            std::env::temp_dir().join(format!("ows-midnight-zswap-outage-{}", std::process::id()));
        let scope = crate::wallet::signing_scope("midnight:preview", Some(&vault));
        let provider = provider();

        let outage = run_zswap_replay(&url, &provider, &scope, "fp", None).await;
        let kept = sync_cache::snapshot_path(&url, "fp", &scope)
            .and_then(|path| sync_cache::try_load_snapshot(&path));
        *cut.lock().unwrap() = None;
        let recovered = run_zswap_replay(&url, &provider, &scope, "fp", None).await;
        let _ = std::fs::remove_dir_all(&vault);

        let err = outage
            .err()
            .expect("a sync the indexer keeps cutting must fail");
        assert!(err.to_string().contains("incomplete"), "{err}");
        let kept = kept.expect("the outage keeps the progress made");
        assert_eq!(kept.last_seen_event_id, 0);

        let recovered = recovered.expect("the sync recovers once the indexer is back");
        assert!(recovered.from_snapshot);
        assert_eq!(recovered.last_seen_id, 5);
        let mut clean = ZswapLocalState::new();
        for e in events() {
            fold_zswap_event(&provider, &mut clean, &e.raw, false).expect("fold");
        }
        let encode = super::super::cache::encode_zswap_state;
        assert_eq!(
            encode(&recovered.wallet).unwrap(),
            encode(&clean).unwrap(),
            "the recovered wallet differs from a clean replay"
        );
    }

    #[test]
    fn resume_is_inclusive_of_last_seen_event() {
        // Warm resume re-fetches the last-seen event (inclusive) so the indexer echoes it
        // and reveals the live max id, instead of tailing past the tip from last_seen+1.
        assert_eq!(resume_subscribe_id(84699), 84699);
        // Genesis (no cursor, GENESIS_CURSOR = -1) starts the replay at event 0.
        assert_eq!(resume_subscribe_id(-1), 0);
        assert_eq!(resume_subscribe_id(0), 0);
    }
}
