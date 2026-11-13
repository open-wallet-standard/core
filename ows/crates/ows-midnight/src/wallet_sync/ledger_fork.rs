//! The history a network wrote before its hard fork to ledger 9.
//!
//! The indexer serves every ledger event in the ledger that wrote it, so on a network that started
//! on ledger 8 the events before the fork carry ledger 8 headers (`midnight:event[v9]:`) and the
//! ones after carry ledger 9 headers (`midnight:event[v14]:`). The two domains cross the fork
//! differently:
//!
//! - **Shielded.** The chain carries the commitment tree across the fork in place and the indexer
//!   does not replay the earlier events, so the wallet folds them with ledger 8 and carries its
//!   state across. Both ledgers write `ZswapLocalState` with the same `zswap-local-state` codec, so
//!   the crossing is a byte round-trip that keeps every coin at its tree index.
//! - **DUST.** After the fork the indexer replays the DUST history as ledger 9 events, so the
//!   earlier events are skipped; folding them as well would count that DUST twice.

use midnight_ledger::events::Event;
use midnight_serialize::{tagged_deserialize, tagged_serialize, Tagged};
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;

type InMemoryDbV8 = midnight_storage_v8::db::InMemoryDB;
pub(crate) type ZswapLocalStateV8 = midnight_zswap_v8::local::State<InMemoryDbV8>;
pub(crate) type EventV8 = midnight_ledger_v8::events::Event<InMemoryDbV8>;

/// Which ledger wrote an event, judged by the version in its header against this build's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EventLedger {
    /// This build's ledger.
    Current,
    /// An earlier ledger: history from before a hard fork.
    Older,
    /// A later ledger than this build knows.
    Newer,
    /// No Midnight event header at all.
    Unknown,
}

pub(crate) fn event_ledger(bytes: &[u8]) -> EventLedger {
    let Some(version) = header_version(bytes, "event") else {
        return EventLedger::Unknown;
    };
    match version.cmp(&current_event_version()) {
        std::cmp::Ordering::Equal => EventLedger::Current,
        std::cmp::Ordering::Less => EventLedger::Older,
        std::cmp::Ordering::Greater => EventLedger::Newer,
    }
}

fn current_event_version() -> u32 {
    let tag = <Event<InMemoryDB> as Tagged>::tag();
    tag.strip_prefix("event[v")
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|digits| digits.parse().ok())
        .expect("the ledger's event tag is event[v<N>]")
}

/// The `N` of a `midnight:<kind>[v<N>]:` header at the start of `bytes`.
fn header_version(bytes: &[u8], kind: &str) -> Option<u32> {
    let rest = bytes.strip_prefix(format!("midnight:{kind}[v").as_bytes())?;
    let end = rest.iter().position(|&b| b == b']')?;
    if rest.get(end + 1) != Some(&b':') {
        return None;
    }
    std::str::from_utf8(&rest[..end]).ok()?.parse().ok()
}

pub(crate) fn decode_event_v8(bytes: &[u8]) -> Result<EventV8, std::io::Error> {
    midnight_serialize::tagged_deserialize(&mut &bytes[..])
}

/// Carry a ledger 8 shielded state across to ledger 9.
pub(crate) fn zswap_to_v9(
    state: &ZswapLocalStateV8,
) -> Result<ZswapLocalState<InMemoryDB>, std::io::Error> {
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(state, &mut bytes)
        .map_err(|e| std::io::Error::other(format!("serialize ledger 8 shielded state: {e}")))?;
    tagged_deserialize(&mut &bytes[..]).map_err(|e| {
        std::io::Error::other(format!("read ledger 8 shielded state as ledger 9: {e}"))
    })
}

/// Carry a ledger 9 shielded state back to ledger 8, to fold more pre-fork events into it (a
/// snapshot saved part-way through the pre-fork history resumes as ledger 9 bytes).
pub(crate) fn zswap_to_v8(
    state: &ZswapLocalState<InMemoryDB>,
) -> Result<ZswapLocalStateV8, std::io::Error> {
    let mut bytes = Vec::new();
    tagged_serialize(state, &mut bytes)
        .map_err(|e| std::io::Error::other(format!("serialize shielded state: {e}")))?;
    midnight_serialize::tagged_deserialize(&mut &bytes[..]).map_err(|e| {
        std::io::Error::other(format!("read ledger 9 shielded state as ledger 8: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_header_tells_which_ledger_wrote_it() {
        let current = format!("midnight:event[v{}]:", current_event_version());
        let older = format!("midnight:event[v{}]:", current_event_version() - 1);
        let newer = format!("midnight:event[v{}]:", current_event_version() + 1);
        assert_eq!(event_ledger(current.as_bytes()), EventLedger::Current);
        assert_eq!(event_ledger(older.as_bytes()), EventLedger::Older);
        assert_eq!(event_ledger(newer.as_bytes()), EventLedger::Newer);
        assert_eq!(event_ledger(b"midnight:event[v9]:"), EventLedger::Older);
        assert_eq!(
            event_ledger(b"midnight:ledger-state[v18]:"),
            EventLedger::Unknown
        );
        assert_eq!(event_ledger(b"midnight:event[v9"), EventLedger::Unknown);
        assert_eq!(
            event_ledger(b"<html>bad gateway</html>"),
            EventLedger::Unknown
        );
    }

    #[test]
    fn a_shielded_state_crosses_between_the_ledgers_byte_for_byte() {
        let v8 = ZswapLocalStateV8::new();
        let v9 = zswap_to_v9(&v8).unwrap();
        let mut v8_bytes = Vec::new();
        midnight_serialize::tagged_serialize(&v8, &mut v8_bytes).unwrap();
        let mut v9_bytes = Vec::new();
        tagged_serialize(&v9, &mut v9_bytes).unwrap();
        assert_eq!(v8_bytes, v9_bytes);
        let back = zswap_to_v8(&v9).unwrap();
        let mut back_bytes = Vec::new();
        midnight_serialize::tagged_serialize(&back, &mut back_bytes).unwrap();
        assert_eq!(back_bytes, v8_bytes);
    }
}
