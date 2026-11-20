//! Disk snapshot for the dust ledger state: the tagged-serialized `DustLocalState` plus the
//! indexer cursor, persisted through the generic [`ows_core::sync_cache`] store via `cache_io`.
//!
//! Stores source state (the ledger state + cursor), never a derived balance — the balance is
//! recomputed from the state on read.

use crate::cache_io::{self, SyncCacheScope};
use midnight_ledger::dust::DustLocalState;
use midnight_serialize::{tagged_deserialize, tagged_serialize};
use midnight_storage::db::InMemoryDB;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 2: the hard fork to ledger 9 wiped every DUST UTXO and generation entry, so a DUST state folded
/// from a network's ledger 8 events describes trees the chain no longer has; the snapshots earlier
/// builds wrote are dropped once and the state is rebuilt from the ledger 9 events.
pub(super) const SNAPSHOT_VERSION: u32 = 2;
const CACHE_SUBDIR: &str = "dust";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DustSyncSnapshot {
    pub version: u32,
    /// Fingerprint of `(indexer_url, chain_id)`; guards against reusing a snapshot from a
    /// different indexer.
    pub indexer_fingerprint: String,
    /// CAIP-2 Midnight chain id; guards against reusing a snapshot from a different network.
    pub chain_id: String,
    /// Hex dust public key; guards against reusing a snapshot for a different dust key.
    pub dust_public_key_hex: String,
    /// Highest dust ledger event id already folded into `state_hex`.
    pub last_seen_event_id: i64,
    /// Chain tip `maxId` when saved; lets a resume at the saved tip settle without new events.
    pub max_id_when_saved: i64,
    /// Indexer block height when the snapshot was written; gates the HTTP-tip fast path.
    #[serde(default)]
    pub block_height_when_saved: i64,
    /// Genesis block hash of the chain the state was synced against (empty when unknown); guards
    /// against resuming across a testnet reset, which keeps the network id.
    #[serde(default)]
    pub genesis_hash: String,
    /// Tagged-serialized `DustLocalState<InMemoryDB>`.
    pub state_hex: String,
}

pub(super) fn snapshot_path(
    indexer_url: &str,
    dust_pk_hex: &str,
    scope: &SyncCacheScope,
) -> Option<PathBuf> {
    cache_io::snapshot_path(CACHE_SUBDIR, indexer_url, dust_pk_hex, scope)
}

/// Only a snapshot of this version: the shared loader also takes older ones, and an older one here
/// is a DUST state from before the fork.
pub(super) fn try_load_snapshot(path: &Path) -> Option<DustSyncSnapshot> {
    cache_io::try_load_versioned(path, SNAPSHOT_VERSION)
        .filter(|snap: &DustSyncSnapshot| snap.version == SNAPSHOT_VERSION)
}

pub(super) fn decode_state(hex_s: &str) -> Result<DustLocalState<InMemoryDB>, std::io::Error> {
    let bytes = hex::decode(hex_s.strip_prefix("0x").unwrap_or(hex_s))
        .map_err(|e| std::io::Error::other(format!("invalid dust state hex: {e}")))?;
    let mut reader: &[u8] = &bytes;
    tagged_deserialize(&mut reader)
        .map_err(|e| std::io::Error::other(format!("failed to decode dust state: {e}")))
}

pub(super) fn encode_state(state: &DustLocalState<InMemoryDB>) -> Result<String, std::io::Error> {
    let mut out = Vec::new();
    tagged_serialize(state, &mut out)
        .map_err(|e| std::io::Error::other(format!("failed to encode dust state: {e}")))?;
    Ok(hex::encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_snapshot(version: u32) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ows-midnight-dust-snapshot-v{version}-{}.json",
            std::process::id()
        ));
        let snap = DustSyncSnapshot {
            version,
            indexer_fingerprint: String::new(),
            chain_id: "midnight:preprod".to_string(),
            dust_public_key_hex: String::new(),
            last_seen_event_id: 1,
            max_id_when_saved: 1,
            block_height_when_saved: 1,
            genesis_hash: String::new(),
            state_hex: String::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&snap).expect("encode")).expect("write");
        path
    }

    /// An earlier build's snapshot holds a DUST state from before the fork, which the shared loader
    /// would still take; only the current version is resumed.
    #[test]
    fn only_a_current_version_dust_snapshot_is_resumed() {
        let earlier = write_snapshot(1);
        let current = write_snapshot(SNAPSHOT_VERSION);
        let earlier_loaded = try_load_snapshot(&earlier);
        let current_loaded = try_load_snapshot(&current);
        let _ = std::fs::remove_file(&earlier);
        let _ = std::fs::remove_file(&current);
        assert!(earlier_loaded.is_none());
        assert!(current_loaded.is_some());
    }
}
