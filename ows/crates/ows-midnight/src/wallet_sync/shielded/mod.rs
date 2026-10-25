//! Shielded (Zswap) balance + wallet sync orchestration.
//!
//! [`sync_wallet`] is the single shielded sync: subscribe to `zswapLedgerEvents` and replay them
//! locally into the full spendable [`ShieldedWalletState`] — the viewing key is never sent to the
//! indexer. Balances are derived from that state via [`balances_from_wallet`].

mod cache;
mod vk_hidden;

use midnight_coin_structure::coin;
use midnight_storage::db::InMemoryDB;
use midnight_zswap::local::State as ZswapLocalState;
use ows_signer::chains::MidnightCryptoProvider;
use std::collections::BTreeMap;

use crate::cache_io::SyncCacheScope;
use crate::ShieldedBalances;

/// Synced shielded wallet state (Merkle tree + spendable qualified coins) used to derive balances
/// and to build Zswap spends (e.g. DApp Connector `makeIntent`).
pub struct ShieldedWalletState {
    pub zswap: ZswapLocalState<InMemoryDB>,
}

/// Hex token-type id (`0x…`) for a shielded coin — the key balances are summed under.
fn token_type_hex(ci: &coin::Info) -> String {
    let t = ci.type_.into_inner();
    format!("0x{}", hex::encode(t.0))
}

/// Per-token balances summed from a synced wallet's qualified coins — projected from the spendable
/// state, never stored. Anyone can encrypt a coin of any value to the wallet, and replayed events
/// are not proof-checked, so a total that overflows is an error rather than a wrapped sum.
fn balances_from_wallet(
    state: &ZswapLocalState<InMemoryDB>,
) -> Result<ShieldedBalances, std::io::Error> {
    let mut balances: ShieldedBalances = BTreeMap::new();
    for (_nul, qci) in state.coins.iter() {
        let ci = coin::Info::from(&*qci);
        let token = token_type_hex(&ci);
        let total = balances.entry(token.clone()).or_insert(0);
        *total = total.checked_add(ci.value).ok_or_else(|| {
            std::io::Error::other(format!("shielded {token} balance overflows u128"))
        })?;
    }
    Ok(balances)
}

/// The one shielded wallet sync — subscribe to `zswapLedgerEvents`, replay into the spendable
/// [`ShieldedWalletState`], and return it; the caller derives balances or builds spends from it.
pub async fn sync_wallet(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedWalletState, std::io::Error> {
    vk_hidden::sync_wallet(indexer_url, crypto_provider, scope, current_block_height).await
}

/// Rehash the synced Merkle tree and confirm it has a root, so coin spends can build a valid
/// membership path. Coin selection (`State::spend`) reads the tree; a sync that left it collapsed or
/// rootless would otherwise fail deep inside spend-building with an opaque error.
pub(crate) fn ensure_shielded_merkle_ready(
    state: &mut ZswapLocalState<InMemoryDB>,
) -> Result<(), std::io::Error> {
    state.merkle_tree = state.merkle_tree.rehash();
    if state.merkle_tree.root().is_none() {
        return Err(std::io::Error::other(
            "shielded Merkle tree has no root after sync; the shielded wallet sync may be incomplete",
        ));
    }
    Ok(())
}

/// Shielded balances for `ows fund balance` — derived from the synced wallet state.
pub async fn get_shielded_balances_for_display(
    indexer_url: &str,
    crypto_provider: &MidnightCryptoProvider,
    scope: &SyncCacheScope,
    current_block_height: Option<i64>,
) -> Result<ShieldedBalances, std::io::Error> {
    let wallet = sync_wallet(indexer_url, crypto_provider, scope, current_block_height).await?;
    balances_from_wallet(&wallet.zswap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::hash::HashOutput;
    use midnight_coin_structure::coin::{Nonce, Nullifier, QualifiedInfo, ShieldedTokenType};

    fn wallet_holding(values: &[u128]) -> ZswapLocalState<InMemoryDB> {
        let mut state = ZswapLocalState::new();
        for (i, value) in values.iter().enumerate() {
            let coin = QualifiedInfo {
                nonce: Nonce(HashOutput([i as u8; 32])),
                type_: ShieldedTokenType(HashOutput([7; 32])),
                value: *value,
                mt_index: i as u64,
            };
            state.coins = state
                .coins
                .insert(Nullifier(HashOutput([i as u8; 32])), coin);
        }
        state
    }

    #[test]
    fn an_overflowing_shielded_total_is_an_error() {
        assert!(balances_from_wallet(&wallet_holding(&[u128::MAX, 2])).is_err());
        let balances = balances_from_wallet(&wallet_holding(&[u128::MAX - 2, 2])).unwrap();
        assert_eq!(balances.values().copied().collect::<Vec<_>>(), [u128::MAX]);
    }
}
