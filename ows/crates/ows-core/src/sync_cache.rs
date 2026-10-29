//! Generic on-disk snapshot store: persist per-wallet / per-chain data between
//! CLI invocations.
//!
//! This is the chain-agnostic mechanism — scope, fingerprinting, path layout,
//! and versioned JSON load/save. A chain wraps it with its own environment
//! knobs and directory naming (see `ows-midnight`'s `cache_io` for the canonical
//! wrapper).

use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

/// Scope for a chain's disk cache — isolates snapshots per wallet and per network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncCacheScope {
    /// Wallet UUID from the encrypted wallet file; isolates cache per wallet.
    pub wallet_id: Option<String>,
    /// Explicit vault root (e.g. `~/.ows` or a custom `--vault-path`).
    pub vault_path: Option<PathBuf>,
    /// CAIP-2 chain id (`midnight:preview`, …); isolates cache per network.
    pub chain_id: Option<String>,
}

impl SyncCacheScope {
    pub fn for_wallet(wallet_id: impl Into<String>, vault_path: Option<&Path>) -> Self {
        Self {
            wallet_id: Some(wallet_id.into()),
            vault_path: vault_path.map(Path::to_path_buf),
            chain_id: None,
        }
    }

    pub fn with_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }
}

/// Lowercase + trim a chain id for stable hashing and comparison.
pub fn normalize_chain_id(chain_id: &str) -> String {
    chain_id.trim().to_ascii_lowercase()
}

/// `chain_id` persisted in snapshot JSON (empty when the scope has none).
pub fn snapshot_chain_id(scope: &SyncCacheScope) -> String {
    scope
        .chain_id
        .as_deref()
        .map(normalize_chain_id)
        .unwrap_or_default()
}

/// True when an on-disk snapshot's `chain_id` matches the active scope.
pub fn snapshot_chain_matches(scope: &SyncCacheScope, snap_chain_id: &str) -> bool {
    match scope.chain_id.as_deref() {
        Some(expected) => snap_chain_id.eq_ignore_ascii_case(expected),
        None => snap_chain_id.is_empty(),
    }
}

/// `$HOME` (or `$USERPROFILE` on Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// 16-byte hex fingerprint of `parts` joined with `|` — stable across runs.
pub fn fingerprint(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            h.update(b"|");
        }
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize()[..16])
}

/// Snapshot file path under `root`, isolated by `scope.wallet_id` when present.
///
/// The id is read from the wallet file, so it names a directory only when it is a single plain
/// path component: `..`, an absolute path or a nested path would let `join` leave `root`, so any
/// other id falls back to the unscoped path.
pub fn snapshot_file_path(root: &Path, scope: &SyncCacheScope, hashed_name: &str) -> PathBuf {
    let file = format!("{hashed_name}.json");
    match scope.wallet_id.as_deref() {
        Some(wid) if is_single_normal_component(wid) => root.join(wid).join(file),
        _ => root.join(file),
    }
}

fn is_single_normal_component(s: &str) -> bool {
    let mut components = Path::new(s).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

/// Best-effort JSON load. Returns `None` on any I/O or decode error.
pub fn try_load<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Load a versioned snapshot; rejects `version == 0` or `version > max_version`.
///
/// Reads the file once so the version check and the deserialized value always
/// come from the same bytes.
pub fn try_load_versioned<T: DeserializeOwned>(path: &Path, max_version: u32) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    let version = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()?
        .get("version")?
        .as_u64()? as u32;
    if version == 0 || version > max_version {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort pretty-JSON save. Errors are silently ignored.
///
/// A snapshot can hold privacy-sensitive wallet state (qualified coins, openings, nullifiers), so
/// on Unix the file is written owner-only (`0o600`) and any parent dirs it creates are `0o700`.
pub fn try_save<T: Serialize>(path: &Path, snap: &T) {
    if let Some(parent) = path.parent() {
        let _ = create_dir_all_private(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(snap) {
        let _ = write_private(path, &bytes);
    }
}

/// Create `dir` (and missing parents) owner-only on Unix; plain recursive create elsewhere.
fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `bytes` to `path` atomically: into a fresh sibling file that is then renamed over `path`,
/// so a crash or a concurrent run never leaves a truncated snapshot behind. The file is owner-only
/// (`0o600`) on Unix, and replacing an existing file tightens a looser one too.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_sibling(path);
    let written = write_new_private(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// A sibling of `path` named for this process and call, so concurrent writers never share one.
fn temp_sibling(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    path.with_file_name(name)
}

/// Create `path` (which must not exist) owner-only on Unix and write `bytes` to disk.
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[test]
    fn wallet_scoped_path_includes_wallet_id() {
        let scope = SyncCacheScope::for_wallet("wallet-abc", None);
        let p = snapshot_file_path(Path::new("/cache"), &scope, "deadbeef");
        assert!(p.to_string_lossy().contains("wallet-abc"));
    }

    #[test]
    fn wallet_id_that_is_not_one_path_component_stays_under_root() {
        for wid in ["../escape", "/abs", "a/b", "..", ".", ""] {
            let scope = SyncCacheScope::for_wallet(wid, None);
            assert_eq!(
                snapshot_file_path(Path::new("/cache"), &scope, "deadbeef"),
                Path::new("/cache/deadbeef.json"),
                "wallet_id {wid:?}"
            );
        }
    }

    #[test]
    fn fingerprint_is_order_and_separator_sensitive() {
        assert_ne!(fingerprint(&["a", "b"]), fingerprint(&["b", "a"]));
        assert_ne!(fingerprint(&["a", "b"]), fingerprint(&["ab"]));
    }

    #[test]
    fn chain_match_semantics() {
        let scope = SyncCacheScope::default().with_chain_id("midnight:preview");
        assert!(snapshot_chain_matches(&scope, "midnight:preview"));
        assert!(!snapshot_chain_matches(&scope, "midnight:mainnet"));
        assert!(snapshot_chain_matches(&SyncCacheScope::default(), ""));
    }

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Versioned {
        version: u32,
        value: u32,
    }

    #[test]
    fn versioned_load_round_trip_and_gating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");

        try_save(
            &path,
            &Versioned {
                version: 2,
                value: 7,
            },
        );
        assert_eq!(
            try_load_versioned::<Versioned>(&path, 3),
            Some(Versioned {
                version: 2,
                value: 7
            })
        );
        // version above the supported max is rejected
        assert_eq!(try_load_versioned::<Versioned>(&path, 1), None);

        try_save(
            &path,
            &Versioned {
                version: 0,
                value: 9,
            },
        );
        assert_eq!(try_load_versioned::<Versioned>(&path, 3), None);
    }

    #[cfg(unix)]
    #[test]
    fn saved_snapshot_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("wallet-id");
        let path = nested.join("snap.json");

        try_save(
            &path,
            &Versioned {
                version: 1,
                value: 1,
            },
        );

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "snapshot file must be owner-only");
        let dir_mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "created cache dir must be owner-only");
    }

    #[test]
    #[cfg(unix)]
    fn saving_replaces_the_snapshot_whole_and_tightens_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");
        std::fs::write(&path, "a much longer, looser-permissioned stale snapshot").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let snap = Versioned {
            version: 1,
            value: 7,
        };
        try_save(&path, &snap);

        let loaded: Versioned = try_load(&path).expect("the saved snapshot parses");
        assert_eq!(loaded.value, 7);
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["snap.json"], "no temp file may be left behind");
    }

    /// Two runs can save the same snapshot at once, a signing call and a balance read for one wallet.
    /// Each save replaces the file whole, so a reader always finds one writer's snapshot, never a
    /// missing, torn or mixed one, and no temp file outlives the saves.
    #[test]
    fn concurrent_saves_never_leave_a_torn_or_mixed_snapshot() {
        #[derive(Serialize, Deserialize)]
        struct Snapshot {
            version: u32,
            cursor: Vec<u32>,
        }
        let snapshot = |writer: u32| Snapshot {
            version: writer,
            cursor: vec![writer; 2048],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.json");
        try_save(&path, &snapshot(1));

        std::thread::scope(|s| {
            for writer in [1, 2] {
                let path = &path;
                s.spawn(move || {
                    for _ in 0..40 {
                        try_save(path, &snapshot(writer));
                    }
                });
            }
            for _ in 0..200 {
                let loaded: Snapshot =
                    try_load_versioned(&path, 2).expect("a reader must always find a snapshot");
                assert!(
                    loaded.cursor.iter().all(|&c| c == loaded.version),
                    "a snapshot mixed two writers"
                );
            }
        });

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, ["snap.json"], "no temp file may be left behind");
    }
}
