# Midnight Support

> Non-normative reference for Midnight in the OWS reference implementation: network
> identifiers, the wallet account, and what each `ows` command does on a `midnight:*` chain.

Midnight is unlike the other chains OWS supports: a single wallet holds value in **three
independent domains** — unshielded (Night), shielded (Zswap), and dust (fees) — each with its
own key and address. That difference reaches most commands, so this page goes command by
command: the code path, the reasoning behind it, and how it differs from the other chains.

Commands with no Midnight-specific behavior work on a Midnight wallet exactly as the generic
docs describe: `fund deposit` (MoonPay only), `pay request` / `pay discover` (x402 only),
`wallet export` / `rename` / `delete`, `mnemonic generate`, `update`, and `uninstall`.

## Network identifiers

OWS registers `midnight:mainnet`, `midnight:preview`, and `midnight:preprod`, with the aliases
`midnight`, `midnight-preview`, and `midnight-preprod` (see 07 — Supported Chains). Midnight is
not limited to these three networks: **any `midnight:<network>` chain id is addressable**, so
ad-hoc feature testnets and private deployments work without registering anything. The
`<network>` reference is carried verbatim into the Bech32m HRP of every Midnight address —
mainnet uses the bare HRP (`mn_addr`, `mn_shield-addr`, `mn_dust`) while every other network
appends `_<network>` (`mn_addr_preview`, `mn_addr_my-feature`, …), so an address on one network
can never be mistaken for one on another. The reference must be a valid Bech32m HRP fragment
that the Midnight SDK also accepts:
lowercase letters, digits 1-9, and hyphens only (no `0`), not starting or ending with a hyphen,
and at most 32 characters (the CAIP-2 reference limit). A malformed or mixed-case reference is
rejected — never coerced to lowercase and never cast to mainnet.

## Wallet accounts (`ows wallet`)

**Purpose:** Midnight is a first-class account in **mnemonic** wallets — `wallet create`,
`import --mnemonic`, and `list` surface a `midnight:*` account automatically. This section
covers how that account is derived, and why **raw private-key** wallets deliberately have no
Midnight account.

### Midnight in the default account set

`ChainType::Midnight` is part of `ALL_CHAIN_TYPES`, the set every universal-wallet command
iterates. So a mnemonic wallet derives a Midnight account with no per-command special-casing —
the signer resolves through `signer_for_chain` like any other chain:

```sh
export OWS_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
ows wallet import --name demo --mnemonic
# Wallet imported: …
#   eip155:1 → 0x9858EfFD232B4033E47d90003D41EC34EcaEda94
#   … other chains …
#   midnight:mainnet → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
```

`wallet info` lists Midnight among the supported chains, and `mnemonic derive` with no
`--chain` includes a `midnight:mainnet` line. The account is the **unshielded (Night)** address
only — one address per chain, like every other chain. The shielded and dust addresses are
derived too (`MidnightSigner::derive_addresses`), with no network access, and printed by
`ows mnemonic derive --chain midnight:<network>` and `ows fund balance` (see
[Fund balance](#fund-balance-ows-fund-balance)).

A universal wallet stores one Midnight account, `midnight:mainnet` under the mainnet HRP.
Preview, preprod, and any other network use the same unshielded key; the network's address is
derived at operation time under its own HRP, the way XRPL testnet shares a key with mainnet.

### The packed signing key, and why it is mnemonic-only

Listing the address needs only the unshielded seed, but *acting* on Midnight needs all three
role seeds. When a Midnight signing key is resolved from a mnemonic, `MidnightSigner::encode_keys`
concatenates the three 32-byte role seeds behind a 4-byte magic prefix `MNK1`, producing a
100-byte opaque signing key:

```
MNK1 || unshielded(32) || shielded(32) || dust(32)
```

`decode_keys` splits it back by position; `encode_keys` looks each seed up **by its path role**,
so the packed order is independent of arrival order. The three seeds come from
`default_derivation_paths` (the role paths under coin type 2400). This bundle only exists via
mnemonic derivation — which is exactly why Midnight has no raw private-key import.

### No raw private-key import

`wallet import --private-key` derives one account per chain from a **single** raw curve key.
That can't produce a Midnight account: the account *is* the three-seed `MNK1` bundle, and a lone
32-byte key is neither the bundle nor usably one-third of it. Rather than manufacture a crippled
or random Midnight address, Midnight opts out via an intrinsic signer gate:

```rust
// ows-signer: ChainSigner default
fn supports_private_key_import(&self) -> bool { true }
// MidnightSigner overrides it to false
```

`derive_all_accounts_from_keys` skips any signer whose `supports_private_key_import()` is false,
so **private-key wallets simply have no Midnight account** — the rest of the import is
unaffected. An import that names Midnight itself (`--chain midnight`, or the bindings'
`import_wallet_private_key`) is refused with `InvalidInput`, since it would otherwise succeed
without the account it asked for. Only mnemonic-backed wallets carry Midnight.

Export needs no Midnight-specific handling either: `wallet export` is wallet-level — it returns
the mnemonic phrase, or (for private-key wallets) the `{secp256k1, ed25519, ed25519_bip32}` keys — never a
per-chain key. A private-key wallet holds nothing Midnight to export; a mnemonic wallet exports
the phrase, which already carries full Midnight capability.

### The three addresses

`MidnightSigner::derive_addresses` decodes a packed key and produces all three addresses for a
network:

- **unshielded (Night)** — `SHA-256(x-only BIP-340 pubkey)`, HRP `mn_addr{suffix}`.
- **shielded (Zswap)** — `coinPublicKey || encryptionPublicKey`, HRP `mn_shield-addr{suffix}`.
- **dust** — the SCALE-encoded dust public key, HRP `mn_dust{suffix}`.

`{suffix}` is empty on mainnet and `_{reference}` on every other network (`mn_addr_preview`,
`mn_shield-addr_preview`, `mn_dust_preview`, …). The wallet account and `derive`'s stdout carry only
the unshielded one; `derive --chain midnight:<network>` and `ows fund balance` print all three, on
stderr, from the keys alone.

### Validation

- `mnemonic_wallet_includes_midnight_account` (`ows-lib/src/ops.rs`) pins the Midnight account a
  mnemonic wallet derives; `privkey_wallet_import_secp_and_ed_curve_keys` asserts a private-key
  wallet has **no** Midnight account, and `privkey_wallet_import_rejects_a_mnemonic_only_chain`
  that an import naming Midnight is refused.
- `midnight_opts_out_of_private_key_import` (`ows-signer/src/chains/midnight.rs`) locks the gate;
  `test_universal_wallet_chains_order_and_count` (`ows-core`) confirms Midnight's place in the
  universal wallet's chain list.
- `midnight_derive_addresses_mainnet_vector` pins the exact three-address output; the packed key
  round-trips via `encode_decode_keys_round_trip` / `midnight_decode_keys_rejects_non_midnight_blobs`.

## Address derivation (`ows mnemonic derive`)

**Purpose:** derive and print a Midnight address from a mnemonic, without touching the vault.

```sh
OWS_MNEMONIC="…" ows mnemonic derive --chain midnight:preview
# → mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
```

The mnemonic is read from `OWS_MNEMONIC` (or stdin), used, and immediately zeroized. No
network access, no wallet file — pure derivation.

### Reproduce it

Every output below comes from the BIP-39 test phrase
`abandon abandon … abandon about` at index 0. The unit tests pin the mainnet line and `e2e/midnight-mnemonic-derive.sh` pins every
line, so you can run these verbatim and match byte-for-byte:

```sh
export OWS_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

ows mnemonic derive --chain midnight:mainnet
# → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
ows mnemonic derive --chain midnight:preview
# → mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
ows mnemonic derive --chain midnight:preprod
# → mn_addr_preprod1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q49ekgd

ows mnemonic derive --chain midnight            # 'midnight' alias resolves to mainnet
# → mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6
ows mnemonic derive --chain midnight:feature-x  # any ad-hoc reference is kept verbatim
# → mn_addr_feature-x1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qgl8r2t
ows mnemonic derive --chain midnight:preview --index 1  # account 1: m/44'/2400'/1'/0/0
# → mn_addr_preview1kpq4jf9d35tjnw0jtx7vaexaavq7xyj0x497pcqzwqetuyrc7nrq37rt92
```

Two things to notice. The mainnet address matches the `midnight_derive_addresses_mainnet_vector`
unit vector exactly. And across mainnet / preview / preprod / feature-x the Bech32m *data*
part is identical (`dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q`) — only the HRP and
its checksum change. One key, one hash; the network id lives in the human-readable prefix.

### What it prints

`ows mnemonic derive --chain midnight:*` prints **only the unshielded (Night) address** on
stdout. `derive` is the generic one-address-per-chain command shared with EVM, Solana,
Bitcoin, etc., and scripts read that one line. The full `Addresses` block that
`ows fund balance` shows, unshielded, shielded and dust together, follows on stderr, so the
shielded and dust addresses are available offline, with no wallet and no indexer:

```
mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
Addresses:
  Unshielded: mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
  Shielded:   mn_shield-addr_preview1ywxc2p9986usecc9xert79afzq4m9x35u62sx0a4e2tc5w6mta5ulwhc432vhrlpnvygfep3pxcdt8tgzfstesrm6tf7hjc5jgpl20g2dm5vg
  Dust:       mn_dust_preview1wwcff2ckd4n5hfj43055td8glwtzkhhf6z88xwf0rpftvgstr7zpx50t9vq
```

Because Midnight is in the wallet's default account set (`ALL_CHAIN_TYPES`), `derive` with no
`--chain` — which enumerates that set — also emits a `midnight:mainnet` line (the default
network). Pass `--chain midnight:<network>` to select preview/preprod or an ad-hoc reference.

### The code path

`commands/derive.rs` is chain-agnostic and routes address derivation through the multi-key
bundle — every chain's key material flows `encode_keys` → `derive_address`:

```rust
let signer = signer_for_chain(&chain)?;                     // → MidnightSigner for midnight:*
let paths  = signer.default_derivation_paths(index);        // three role paths for Midnight
let keys   = HdDeriver::derive_keys_from_mnemonic_cached(&mnemonic, "", paths, curve)?;
let signing_key = signer.encode_keys(&keys)?;               // packed MNK1 bundle
let address = signer.derive_address(signing_key.expose())?; // unshielded address
```

For Midnight, `signer_for_chain` resolves to `MidnightSigner`, `curve()` is secp256k1, and
`default_derivation_paths` returns the three role paths. `encode_keys` packs the derived
seeds into the `MNK1` bundle; `MidnightSigner::derive_address` decodes it back to the
unshielded seed and builds the address. A single-key chain's `encode_keys` returns its one
key unchanged, so the same call shape serves every chain. `MidnightSigner::derive_address`
accepts only an `MNK1` bundle: a bare imported key fails the magic check and is rejected, which
is what makes Midnight's opt-out from private-key import safe (see
[Wallet accounts](#wallet-accounts-ows-wallet)).

### How the unshielded address is built

`MidnightSigner::derive_unshielded_address_with_hrp` (`ows-signer/src/chains/midnight.rs`):

1. Interpret the 32-byte seed as a secp256k1 **BIP-340 Schnorr** signing key.
2. Take its 32-byte **x-only** public key (`verifying_key().to_bytes()`).
3. `SHA-256` that public key.
4. Bech32m-encode the 32-byte hash under the network's unshielded HRP.

The HRP is `mn_addr` on mainnet and `mn_addr_{reference}` on every other network. The
network `reference` is the CAIP-2 part after `midnight:`, kept **verbatim** (it must already be
lowercase; an uppercase reference is rejected, not lowercased) and never mapped to a fixed set — so `midnight:preview`, `midnight:preprod`, and any ad-hoc
feature testnet like `midnight:feature-x` all derive a correctly-tagged address
(`mn_addr_preview…`, `mn_addr_preprod…`, `mn_addr_feature-x…`) rather than being cast to
mainnet or rejected. This follows the Midnight WalletEngine specification for the Night
address.

### Why the derivation looks the way it does

Midnight uses a **multi-role** BIP-44 tree rather than the single derivation path most
chains use:

```
m/44'/2400'/{index}'/{role}/0
            ^account  ^role: 0 = unshielded (Night), 2 = dust, 3 = shielded (Zswap)
```

- **SLIP-44 coin type `2400`** identifies Midnight.
- **`--index` selects the hardened BIP-44 account**, and each role's key sits at address
  index `0`. Lace numbers its Midnight wallets the same way, so `--index N` reaches the same
  keys as account `N` there. The default, `--index 0`, is account `0'`.
- The three **roles** produce the three independent domain seeds.

A wallet stores the account it was imported at. Without `--index`, `sign tx`, `sign send-tx` and
`sign message` act on that stored account, as `fund balance` does, so a wallet imported with
`--index 2` signs with account 2's keys; every other chain keeps the default of `0`. An explicit
`--index` still wins, from the owner and from an api-key token alike.

`derive` prints only the unshielded (role 0) address, but — because address derivation
routes every chain through the bundle — it assembles the full three-seed `MNK1` bundle and
`derive_address` extracts role 0 from it. That same packed bundle is what the shielded and
dust operations use to *act* in those domains — see
[the packed signing key](#the-packed-signing-key-and-why-it-is-mnemonic-only).

The role constants and path builder live in one place (`MidnightSigner::derivation_path`
/ `role_from_path` / `account_from_path`) so the coin type and address index are a single
source of truth, a derived key can be mapped *back* to its role when the bundle is decoded,
and a stored path can be mapped back to its account when the wallet's keys are unsealed.

### How this differs from other chains

| | Other chains | Midnight |
|---|---|---|
| Addresses per account | 1 | 3 (unshielded / shielded / dust) |
| What `derive` prints | the address | the **unshielded** address only |
| Derivation | one path | three role paths under coin type 2400 |
| Address math | curve-specific (keccak, base58, …) | Bech32m of `SHA-256(x-only BIP-340 pubkey)`, network HRP |

### Validation

Unit vectors in `ows-signer/src/chains/midnight.rs` lock the derivation:

- `midnight_derive_addresses_mainnet_vector` pins the exact mainnet unshielded / shielded /
  dust address bytes for the abandon-phrase test wallet.
- `midnight_preview_unshielded_address_uses_preview_hrp` and
  `midnight_derive_addresses_preview_uses_preview_hrps` confirm the preview HRPs
  (`mn_addr_preview…`, `mn_shield-addr_preview…`, `mn_dust_preview…`).
- `midnight_from_chain_id_preserves_arbitrary_reference` confirms an ad-hoc `midnight:feature-x`
  network derives `mn_addr_feature-x…` instead of falling back to mainnet;
  `midnight_rejects_malformed_network_reference` confirms an uppercase, empty, `0`-containing,
  over-32-character or non-`midnight:` id is rejected rather than coerced.

## Fund balance (`ows fund balance`)

**Purpose:** read a Midnight wallet's balances from the indexer — the public unshielded
(Night) UTXOs, the private shielded (Zswap) coins, and the DUST fee ledger — for any
`midnight:<network>`.

```sh
ows fund balance --wallet demo --chain midnight:preview
```

A `midnight:*` chain routes to the Midnight indexer instead of the MoonPay path the other
chains use. The unshielded balance needs only the stored address, so it's always shown; the
**shielded** and **DUST** balances need the wallet's key material, from `OWS_PASSPHRASE` (an
owner passphrase or an api-key token). With `OWS_PASSPHRASE` unset the empty passphrase is tried,
as the signing commands do, so a wallet imported with `wallet import` (which sets no passphrase)
needs nothing set. When no credential opens the wallet, the shielded section is left out, the
dust section shows only its NIGHT-registration summary with `DUST seed: unavailable`, and the
command prints:

```
note: set OWS_PASSPHRASE to read Midnight shielded/dust balances
```

An `OWS_PASSPHRASE` that is set but does not open the wallet is an error, not a fallback.

### What it prints

Amounts print to **stdout** as `{amount:>24} {token_type}`; status, addresses, and headers go
to **stderr**, so balances pipe out cleanly. Check the exit status as well: a balance stream that
failed exits non-zero (see [Dust (fees)](#dust-fees)). A Preview run (values illustrative):

```
Addresses:
  Unshielded: mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
  Shielded:   mn_shield-addr_preview1…
  Dust:       mn_dust_preview1…

[ows-midnight] syncing balances from indexer (may take a while on first run)…
Unshielded balances:
              1000000000 0000000000000000000000000000000000000000000000000000000000000000

Shielded balances:
                  500000 0x5cd36fe5ed159246257b476bb67bc8266290581ef3844fcabd7c134b3f8b03ea

Dust status (fees):
  NIGHT UTXOs: total=3 registered=2 unregistered=1
  Fee mode: generationless DUST (can be derived from unregistered NIGHT inputs)
  DUST seed: available
  DUST UTXOs: 4
  DUST balance (specks): 12345678900000000
  DUST balance: 12.345678900000000 (best-effort, wall-clock time)
```

The `Addresses` block re-encodes the stored address to the target network's HRP and adds
shielded/dust when a key is available (else `(unavailable)`). It derives from the keys alone and
prints before the indexer is resolved, so it shows before a first sync that can take minutes, and
also when no indexer is configured for the network, where the command then stops with that
error. Unshielded token types are the
indexer's `tokenType` as sent (NIGHT is 64 zeros); shielded ones are the coin's token type as
`0x`-prefixed hex. An empty section says so — `none — no unshielded tokens found
for <address> on <chain_id>` / `none — no unspent shielded coins found after full sync`.

### The credential

`OWS_PASSPHRASE` carries one of two things, resolved before syncing:

- **An owner envelope passphrase** — decrypts the packed `MNK1` role seeds and builds the
  `MidnightCryptoProvider` that derives the shielded/dust keys.
- **An api-key token** (prefix `ows_lib::key_store::TOKEN_PREFIX`) — routes through the same
  policy-enforcing channel as `sign-message` / `sign-transaction`, so a scoped token reads
  shielded/dust balances without the raw passphrase.
- **Unset** — the empty passphrase is tried; when it doesn't open the wallet, the shielded and
  DUST balances are left out, with the `note:` above.

The keys are unsealed at the account's stored index (the hardened account segment of its derivation path), so
the shielded and dust keys always belong to the stored unshielded address. The passphrase is
removed from the environment and the unsealed key is dropped as soon as the provider is built, so
neither lives through the sync; the provider itself holds the role seeds and the keys derived
from them until the command ends.

A private-key wallet has no Midnight account (see
[Wallet accounts](#wallet-accounts-ows-wallet)), so the command fails with
`wallet has no account for chain`.

### The three balance streams

#### Unshielded (Night)

From the indexer's UTXO set for the address, summed per token type. Needs no key, resumes from
its snapshot but always catches up over the WebSocket (it has no at-tip fast path), and drives the
DUST-registration summary below.

#### Shielded (Zswap)

OWS subscribes to the full, unfiltered `zswapLedgerEvents` stream and replays it **locally**
through the crypto provider (`fold_shielded`) into a full spendable wallet state
(`ShieldedWalletState` / `ZswapLocalState`, keyed by nullifier); balances sum its coins. The
viewing key never leaves the process, and the number is **authoritative**: it sums the wallet's
own unspent coins, tracked by nullifier. First sync is slow (full replay); the snapshot cache
(below) makes later runs fast.

#### Dust (fees)

The dust-fee section shows only when the **network's dust ledger is live** — decided at run time,
not by network name. OWS probes the indexer's `dustLedgerEvents` tip cursor: a positive `maxId`
means an active ledger (shown); a missing or empty stream hides it. So dust appears
wherever the ledger is active — Preview/Preprod today, **mainnet automatically once its ledger
goes live**, no OWS change. The probe needs no wallet key (the tip is chain-global).

A DUST read that fails does not pass for a complete one. When the dust stream cannot be opened for
the probe, or the DUST ledger does not sync, the command still prints the unshielded and shielded
balances (and `DUST: unavailable (…)` in the dust section), then exits non-zero with
`error: partial balance: …` on stderr. Having no credential to sync the DUST ledger with is not a
failure: that shows `DUST seed: unavailable` and exits 0.

The ledger is replayed through the provider (`fold_dust`) and the balance is computed against the
wall clock as read when the command starts, since DUST decays — hence
`best-effort, wall-clock time`. The
NIGHT-registration summary (`total`/`registered`/`unregistered`) comes from the public UTXOs, so
it shows even without a key, and picks the fee mode: *generationless DUST* when unregistered NIGHT
inputs exist, *DUST spend proofs* otherwise.

### Concurrency

The three streams are independent subscriptions with independent caches, so they sync
concurrently, each on its own thread; wall-clock cost is the **slowest** stream, not the sum, and
a long fold in one stream never leaves another stream's socket unread. A block-height read plus a per-stream live-tip probe gate the shielded/dust fast-paths and
the stale-snapshot check; the unshielded stream has no fast path and always catches up.

### Snapshot cache

Each stream persists its **source state** (UTXO set / Zswap wallet state / dust ledger — never a
derived balance) to disk, so a warm run resumes instead of replaying from genesis:

```
{vault}/chains/midnight/cache/{unshielded|shielded|dust}/{wallet_id}/<hash>.json
```

The `<hash>` fingerprints `(indexer_url, chain_id, key)`, so a snapshot is never reused across a
different indexer, network, or key. Every snapshot also records the **genesis block hash** of the
chain it was synced against, and each stream discards a snapshot whose hash differs from the
indexer's current one (`block(offset: { height: 0 }) { hash }`): a testnet reset keeps the network
id but starts a new chain, and once the new chain's event ids pass the saved cursor the tip check
below no longer sees the reset. A snapshot with no recorded hash is discarded as well; if the
genesis query fails, the snapshot is kept and checked on the next run.

On resume the shielded/dust streams **validate the snapshot against the live stream tip**
(`tip_verify`) by probing the indexer's current `maxId`:

- **discard** it and replay from genesis when the saved cursor sits *past* the live tip — the sign
  of an indexer reset that rewound the event ledger, where resuming would otherwise report the old
  chain's stale balances;
- **skip the WebSocket catch-up** and return the on-disk state when the cursor already sits *at* the
  live tip (when the tip probe gets no answer, an unchanged block height is accepted instead);
- otherwise replay forward from the saved cursor to catch up.

A shielded or dust snapshot the live events do not fit is stale whatever those checks said: when
the next event fails to fold into it (its commitment tree rejects the insertion index), it is
discarded and the stream replays from genesis. Snapshots are written to a temporary file and
renamed into place, so an interrupted run never leaves a truncated one behind.

`OWS_MIDNIGHT_SYNC_CACHE=0` disables disk caching.

### Configuration

The GraphQL indexer URL comes from `~/.ows/config.json` under `rpc["midnight:<network>"]`; the
WebSocket endpoint is that URL's path plus `/ws`, with any query kept. Only preview ships a
default, since it is the only network with a public indexer that needs no API key. For mainnet
and preprod, set the URL yourself: Midnight's
[networks guide](https://docs.midnight.network/guides/networks-and-environments) lists the hosted
endpoints, which take a per-network API key in a `?project_id=` query, or point it at your own
indexer (for example `http://localhost:8088/api/v4/graphql`). A plaintext `http://` or `ws://` URL
is accepted only for an indexer on this machine, as for the node and the proof server, since the
connection carries the API key and the wallet's addresses. Credentials in the URL (user info,
query) never appear in error messages and are left out of the snapshot cache key, so rotating a
key keeps the snapshots, while switching to another indexer starts a fresh sync. Sync timeouts
default to HTTP 30s, WS connect 30s, WS idle 90s, and stall 120s, each overridable from the
environment for a cold wallet on a slow link or a degraded-but-progressing indexer.

### Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; unlocks shielded/dust (`LWS_PASSPHRASE` is read when it is unset). Unset → the empty passphrase is tried; if that fails, the shielded and DUST balances are left out. Set but wrong → error. |
| `OWS_WALLET` | Default for `--wallet`. |
| `OWS_MIDNIGHT_SYNC_CACHE` | `0`/`false` → disable the disk snapshot cache (always re-sync). |
| `OWS_MIDNIGHT_WS_IDLE_TIMEOUT_SECS` | WebSocket idle budget per stream. Default `90`. |
| `OWS_MIDNIGHT_STALL_TIMEOUT_SECS` | Seconds without events before a stream is declared stalled. Default `120`. |
| `OWS_MIDNIGHT_INDEXER_HTTP_TIMEOUT_SECS` | Per-request timeout for indexer GraphQL HTTP calls. Default `30`. |
| `OWS_MIDNIGHT_WS_CONNECT_TIMEOUT_SECS` | Timeout for establishing the indexer WebSocket. Default `30`. |

Each timeout takes a positive whole number of seconds; a zero, negative, or unparseable value
is ignored with a warning on stderr and the default is used. Overriding is safe in both
directions — a longer budget only gives a sync more room to finish, and a shorter one surfaces
as a stall error or a missing dust section, never as a partial balance reported as complete.

### The code path

- CLI: `commands/fund.rs::balance` detects a `midnight:*` chain, resolves the credential, builds
  the optional `MidnightCryptoProvider`, and calls `ows_midnight::print_fund_balance`.
- Display + concurrency: `ows-midnight/src/fund_balance.rs`.
- Streams (`wallet_sync/`): `unshielded.rs`, `shielded/` → `shielded/vk_hidden/` (the local
  Zswap replay), `dust/`.
- Cache + gating: `cache_io.rs` (which also reads `OWS_MIDNIGHT_SYNC_CACHE`), `shielded/cache.rs`,
  `shielded/vk_hidden/sync_cache.rs`, `dust/sync_cache.rs`, `tip_verify.rs`; the unshielded
  snapshot code lives in `unshielded.rs`.
- Sync timeouts and their environment overrides: `midnight_env.rs`.

## Transactions on Midnight

On Midnight a transaction is a zero-knowledge-proven artifact rather than plain signed bytes,
and the wallet — not the DApp — balances it and pays the fee. The signing commands below share
two ideas.

### Intents and segments are not the same thing

These two words are easy to blur, and several commands depend on the difference.

An **intent** is *physical* structure: a transaction carries a map of them, keyed by a `u16`
**intent id**. One intent bundles a guaranteed unshielded offer, a fallible unshielded offer,
contract actions, and dust actions — the unit the wallet authorizes together, with one
signature and one binding commitment.

A **segment** is *logical* execution structure: the unit the ledger applies atomically.
A transaction executes in segments, and there are two kinds:

- **Segment 0, the guaranteed segment** — assembled **across every intent**: the guaranteed
  half of *all* of them applies together, as one all-or-nothing unit. It is not any single
  intent's segment, which is exactly why no intent may be keyed at id 0.
- **A fallible segment** — one per intent that has a fallible half, allowed to fail on its
  own without reverting segment 0. Its segment id **is** that intent's id.

So the id `7` names *one intent* and *its fallible segment*, while that same intent's
guaranteed half executes in segment 0 alongside every other intent's. The ledger keeps both
coordinates on every event it emits — `logical_segment` (which segment executed it) and
`physical_segment` (which intent contributed it).

Two consequences run through the sections below: a value movement is reported per **segment**
(what will execute together), while `makeIntent`'s `intentId` names an **intent** — and
because that id doubles as the intent's fallible segment id, `0` is rejected.

### The seed-free crypto provider

`ows-midnight` (the crate that does all the network orchestration — balance sync,
connector balancing, dapp-connector methods) holds **no raw key material**. All key
derivation and key-bearing work is owned by `ows-signer` behind a per-account capability
object, `MidnightCryptoProvider`:

- `MidnightSigner` is **stateless** — network identity, HRPs, address derivation,
  encode/decode of the packed key. It is the factory: `signer.crypto_provider(&credential)`
  decodes the packed blob **once**.
- `MidnightCryptoProvider` is **stateful, per-account** — it owns the decoded seeds and
  the derived Zswap/dust keys, and exposes only *public* values (verifying key, dust
  public key, addresses) plus *keyful-but-opaque* operations (fold a ledger event into
  wallet state; authorize a shielded input or dust fee). The typed secret keys never
  leave the provider.

`ows-lib` sits at the boundary: it holds the credential, builds one
`MidnightCryptoProvider`, and hands only `&provider` into `ows-midnight`. This is why
`fund balance` and `sign tx` both route through `ows-lib` first — it is the only layer
that ever touches the decrypted key.

The provider derives its Zswap and dust keys from their seeds once, when it is built; listing
addresses, which the signing path does many times, reads the held keys and derives no secret key
again. The one place secret material passes through `ows-midnight` is proving: the signer hands
each spend's proof preimage, whose witnesses include the coin or dust secret key, to
`ows-midnight`'s `Prover`. Proving locally keeps it in the process. Proving remotely serializes it
into a request buffer sized to fit, so it is never reallocated and copied, which is handed to the
HTTP client without a copy and wiped when the client drops it; the TLS and IO layers' own buffers
are beyond its reach. The `no_key_material_gate` test keeps that channel narrow: only the prover
and the outputs-only mock prover take preimages, no production code Debug-formats one, and a
remote proof server is used only when the vault's config names one.

## Sign and seal (`ows sign tx`)

**Purpose:** turn a DApp Connector request into a fully proven, signed, **sealed**
transaction — without broadcasting it.

```sh
OWS_PASSPHRASE= ows sign tx --chain midnight:preview --wallet length-wallet --json --tx '{
  "method": "makeTransfer",
  "desiredOutputs": [
    { "kind": "unshielded", "type": "night", "value": "1000000", "recipient": "<mn_addr…>" }
  ],
  "options": { "payFees": true }
}'
# → { "recovery_id": …, "signature": "…", "transaction": "0x…sealed hex" }
```

On every other chain, `sign tx` accepts hex-encoded unsigned transaction bytes and returns
a signature. On Midnight the wallet **is** the DApp Connector: the `--tx` argument is a
JSON connector request describing *what the user wants*, and the wallet constructs,
balances, proves, signs, and seals a complete transaction. `sign tx` seals it and returns
the sealed hex on `SignResult.transaction`; it does **not** broadcast. (Broadcasting is
[`sign send-tx`](#sign-and-send-ows-sign-send-tx).)

### Why `--tx` is JSON, not hex

`decode_tx_input` (`ows-lib/src/ops.rs`) hex-decodes for every chain **except** Midnight,
where it normalizes the argument into a connector request (a bare MIP-0005 `zswapoffer` or hex
transaction is wrapped into the request that carries it) and passes the JSON on as UTF-8 bytes.
This is because a Midnight connector request is a JSON document, not a wire transaction, and it
must be parsed by the *key-aware* step (the wallet's own inputs are needed to balance it).
Decoding needs no key, so it can run before policy evaluation on the agent path.

### The pipeline

```
decode_tx_input            normalize the connector request (no key)
        │
prepare_signable_tx        the key-aware step (ows-lib):
        │   ├─ build ONE MidnightCryptoProvider from the credential (ows-lib holds the key)
        │   ├─ plan_connector_tx       → an inert ConnectorPlan (no proofs, no signatures)
        │   ├─ plan.policy_context(…)  → chain_extra: the wallet-relative movement per segment,
        │   │                            the contracts it calls, and the rest of the plan's context
        │   ├─ ── POLICY SEAM ──       gate(chain_extra)   ← second, effect-aware policy pass
        │   └─ plan.authorize(…)       → build + prove + sign the binding + serialize
        │
sign / seal                extract signable bytes, sign, encode_signed_transaction (seal)
        │
SignResult.transaction     the sealed, submit-ready tx hex (NOT broadcast)
```

The key design point is that **the plan is inert** — `ConnectorPlan` carries no bearer
instrument (no proofs, no signatures). That lets the wallet derive the transaction's
*effects* and run a policy check on them **before** any expensive proving happens. If the
policy denies, the key is dropped unused and nothing is ever proved.

`ows-lib` is the only layer that touches the decrypted key: it builds the
`MidnightCryptoProvider` once and hands only `&provider` into `ows-midnight`.

### Owner mode vs agent (token) mode

`sign tx` reads `OWS_PASSPHRASE`:

- **Owner passphrase** → decrypt the key directly, full authority. `prepare_signable_tx`
  is called with a gate that always allows — no policy at all.
- **API token** (`ows_key_…`) → two policy passes:
  1. **First pass** (`enforce_policies_and_decrypt_key`) — before the key is released,
     the request's *shape* is gated. `make_transaction_context` surfaces the raw request;
     `effects` is empty and there is no `chain_extra`, because nothing has been planned
     yet. Every policy on the key runs: declarative rules (allowed chains, expiry, …) and
     executables.
  2. **Second pass** (the policy seam, `enforce_effect_policies`) — after planning, the
     plan's key-derived, wallet-relative **effects** are filled in under `chain_extra` and
     every policy runs again: the declarative rules are re-checked, and the executables
     now see the effects.

Both `sign tx` and `sign send-tx` run this same two-pass connector pipeline on the agent
path — `sign_and_send` routes Midnight through `decode_tx_input` + `prepare_signable_tx`
exactly as `sign tx` does. The only difference is the tail: `sign tx` seals and returns
the hex; `sign send-tx` also broadcasts. So a policy denial at either pass blocks a
broadcast too — the transaction is never proved, let alone submitted.

### The four connector methods

`plan_connector_tx` routes on the request's top-level `method`. An **absent** `method`
resolves to `balanceUnsealedTransaction`, the wallet's original (pre-multi-method)
behavior. Each method has its own submodule under `ows-midnight/src/dapp_connector/`.

#### `makeTransfer`

*"Send these outputs."* The wallet builds an outputs-only transaction (a deliberate
deficit), then balances it with its **own** inputs, proves, signs, and seals. Fees are
paid in **dust**, never in the transferred token.

- Unshielded outputs ride the **fallible** offer of intent 1, and the wallet funds them from its
  NIGHT inside that same offer, with the change: the whole NIGHT leg executes in segment 1, which
  keeps it off the guaranteed section's tight time-to-dismiss budget. The intent id cannot be 0,
  which names the guaranteed segment that every intent shares; the ledger rejects an intent declared
  there (surfaced on-chain as `Custom error: 167`). So the effects report the NIGHT outflow at
  segment 1, and a landed transfer can partly fail: the fee is spent even if the NIGHT leg is not.
- Shielded outputs ride the guaranteed Zswap offer directly, in segment 0 with the DUST fee.
- The outputs-only proven transaction reuses the same `plan_unsealed_proven_tx →
  authorize_proven_tx` tail as `balanceUnsealed` — one "diagonal" that every method funnels
  into.

#### `makeIntent`

*"Build a maker swap offer."* The wallet contributes real inputs and declares wanted
outputs, producing a deliberately **imbalanced** maker offer (a swap intent). `sign tx`
seals it as a fully-sealed offer (`proof,pedersen-schnorr`) for hand-off to a taker.
Shielded *inputs* to a maker offer are supported — the wallet selects whole shielded coins,
returns the excess as change to the maker, and the spend witnesses are built and proved in
the signer.

**`options.intentId`** — the id the maker's intent keys at, per the spec: a number, or
`"random"` to let the wallet draw one (its suggested mode for swaps; a wide draw is what keeps
two independently-built intents from colliding when the taker merges its own in). Omitted, it
is `1`. Id `0` is rejected — it names the guaranteed segment, which spans all intents rather
than being any one intent's, so the ledger rejects an intent declared there (`Custom error:
167`) — as is anything past the 16-bit id space. The id doubles as the segment id of this
intent's fallible half, which is what a policy reading effects sees.

**`options.payFees`** — `true` is **rejected** here, with an error saying so. A maker offer is
imbalanced and fee-free by construction: the taker funds the DUST fee when it completes the
swap. The spec's blanket default for `payFees` is `true`, but its own reference SDK defaults
`initSwap` to `false`, and an error is the honest answer to a request this wallet cannot
satisfy — better than returning an offer that quietly does the opposite. Omitted or `false`
builds the fee-free offer. (The other three methods do honor `payFees` in both directions.)

**`options.ttl` — when the offer expires.** Optional; Unix epoch seconds. Omitted, the wallet
picks the widest window the ledger accepts (`global_ttl` past now — currently an hour, and the
reference wallet SDK's default too), which is what every offer got before this option existed.

The expiry matters more here than on the other methods. `Intent.ttl` is inside the seal cover
and `makeIntent` runs no balancing tail, so **nothing downstream can change it** — not the
taker, not a service relaying the offer. It is also the maker's only unilateral way out: a
sealed offer is a bearer artifact, cancellable only by letting it expire or by double-spending
one of its inputs. A maker quoting a price it re-quotes often is therefore writing a free option
against itself for the whole window, and wants a short one:

```sh
# this quote stands for 30 seconds
"options": { "ttl": 1785878998 }
```

The request is rejected at parse — before any proving is paid for — if the instant is not in the
future (born expired) or is further than `global_ttl` ahead, the two bounds the ledger enforces
against the block the offer lands in (`IntentTtlExpired`, `IntentTtlTooFarInFuture`).

The expiry is fixed when the offer is planned, the default included, and the policy pass sees it
as `chain_extra.offer` (see
[How long a maker offer stands](#how-long-a-maker-offer-stands--chain_extraoffer)), so a policy can
cap an agent's offers without parsing the request.

A taker has to land the merged transaction inside the maker's TTL, and its own tip-aligned TTL does
not extend it — the ledger checks each intent's TTL separately. So `balanceSealedTransaction` refuses
an offer that expires within a minute of the chain tip.

> `ttl` is **not** in the DApp Connector specification, which defines no expiry option on any
> method and leaves the choice to the wallet. It is an OWS extension, kept optional precisely so
> that a spec-compliant dApp that never sends it is unaffected, and proposed upstream for the
> spec to adopt.

**Withdrawing an offer before it expires.** No connector method cancels a published offer, and none
outside the specification is added: the wallet cannot spend the inputs of one offer in particular,
since no request names the coins it spends. What it can do is spend every coin an offer could have
used. A `makeTransfer` to the wallet's own address of its whole balance of the offered token, read
with `ows fund balance` just before (and of its whole NIGHT balance too, as another output of the
same request, if the offer spends NIGHT), selects every coin of that token and returns the value in
new coins, so every open offer that spends any of them can no longer complete:

```json
{"method":"makeTransfer","desiredOutputs":[
  {"kind":"shielded","type":"<offered token>","value":"<whole balance>","recipient":"<own mn_shield-addr…>"}]}
```

Use `"kind":"unshielded"` and the wallet's own `mn_addr…` for an unshielded token. It withdraws all
of the wallet's offers in that token at once, not one, and it costs a DUST fee like any transfer. A
transfer of the wallet's whole NIGHT leaves no NIGHT coin to register for the fee, so the fee is then
paid from DUST the wallet already holds. An unshielded transfer's leg is fallible (see
[`makeTransfer`](#maketransfer)), so the offer is withdrawn once that leg has landed. The same
mechanism withdraws offers by accident: any transfer that happens to select an offer's coin, or the
fallible consolidation that folds leftover unregistered NIGHT, leaves that offer unable to complete.

#### `balanceSealedTransaction`

*"Complete a maker's offer as the taker."* The maker offer is **fully sealed**
(`proof,pedersen-schnorr`), and its binding fixes its value balance, so the taker can't balance
it in place: it completes it by **MERGING**. It builds the per-token complement of the maker's
imbalance, funds the merged tx's DUST fee, seals its half, and `Transaction::merge`s the two.

- The maker is given as hex, a bare `swapoffer` bech32 (MIP-0005), or a MIP-0006 offer
  payload; each decodes to the same sealed offer.
- A **proven** (`proof,embedded-fr`) transaction is refused; `balanceUnsealedTransaction`
  balances one in place.
- The maker must keep all its value in the guaranteed section (segment 0). One with coins, an
  unshielded offer, or an imbalance in a fallible segment is refused, since that segment could
  fail on its own while the taker's payment stands.
- The maker must both give and want a token, in whatever form it arrives (MIP-0006): a give-only
  or want-only transaction is refused, as is one already balanced. So is a maker built for another
  network, before the taker's half is proven.
- Before it plans its half, the taker checks the maker against the chain tip, as MIP-0005 asks of a
  receiver. It refuses an offer whose earliest intent TTL is less than a minute past the tip, since
  the merged transaction could not land in time. It refuses one whose proofs or signatures do not
  verify, checked as the node's well-formedness check does: the zswap proofs against the ledger's
  built-in verifier keys, the signature on every unshielded input and dust registration, each
  intent's binding and the Pedersen binding of the whole, and the TTL window. And it refuses one
  that spends an unshielded coin the indexer no longer lists as unspent: the maker has spent it to
  withdraw the offer, or another taker has already completed it. A checked-in sealed maker whose
  coins a submission has spent is therefore refused at planning, not by the node.
- What needs chain state the taker does not hold is left to the node, which rejects the merged
  transaction whole: a contract call's proof (the contract's verifier key is on chain), a DUST
  spend's proof (it commits to tree roots the indexer does not expose), and the liveness of a
  shielded input (the indexer has no nullifier lookup, and the Merkle root's recency window is the
  node's). A maker whose shielded coin is already spent still fails only at submission, which is
  why the checked-in proven makers in `e2e/shielded-movement-cap/` are single-use.
- The taker pays the merged transaction's fee as the wallet pays its own (see
  [Fees are always dust](#fees-are-always-dust)): with a generationless registration when it holds an
  unregistered NIGHT coin that has generated enough DUST, so a wallet freshly funded with NIGHT can
  complete a swap, and with a spend of DUST it holds otherwise. The registration draws only on NIGHT
  its own intent spends, so the taker's half also spends that coin and returns it whole. A merge that
  swaps unshielded tokens alone is small enough that the node's time-to-dismiss floor rejects it with
  either fee section; a swap with shielded coins on either side clears it.

#### `balanceUnsealedTransaction`

*"Balance this proven, unsealed transaction against my inputs."* The dApp hands the wallet
an already-**proven** (`proof,embedded-fr`) transaction; the wallet balances it, signs, and
seals. This is the original method (and the default when `method` is absent).

- A `proof-preimage` transaction is **rejected** with a precise "out-of-spec, not
  unsupported" message — the dApp must prove its own part first.

> The only **rejected-by-design** input is a `proof-preimage` maker (above) — out of spec,
> not unsupported. `makeIntent` shielded inputs, the sealed-maker merge, and the MIP-0005 /
> MIP-0006 offer forms are all supported.

### Fees are always dust

Every method pays fees in **dust**, sized against the node's real fee gate. Two fee modes
exist depending on the wallet's NIGHT registration state:

- **Generationless DUST** — when the wallet has *unregistered* NIGHT inputs, a dust
  registration is derived from them on the fly.
- **DUST spend proofs** — when all NIGHT is already registered, existing dust is spent with
  proofs.

Fee sizing is done by mock-proving the shielded/dust fragments offline (through the crypto
provider's `build_preimage_dust_spends`) so the fee is right before the real proof is
built. The best-Dust NIGHT coin is reserved for the fee registration, and leftover NIGHT is
rotated through a fallible offer so change returns cleanly. Which mode a plan takes, the most
DUST it can burn and the registration it signs reach the policy pass as `chain_extra.fee` and
`chain_extra.dust_registrations` (see
[How the wallet pays](#how-the-wallet-pays--chain_extrafee-and-chain_extradust_registrations)).

### The effect model (what the policy seam gates on)

`ConnectorPlan::segment_effects` computes the transaction's **wallet-relative net
movement**, grouped by the **segment** each piece executes in — not by the intent that
carried it. Segment `0` is the guaranteed one (applied unconditionally once the tx lands,
pooling the guaranteed halves of every intent); a non-zero segment is one intent's fallible
half, which may revert on its own, and its id is that intent's id. Within a segment it is one
`TransactionEffect` per value domain that nets non-zero, keyed by the wallet's own address for
that domain. (Intent versus segment is spelled out in
[Intents and segments](#intents-and-segments-are-not-the-same-thing).) How it is derived depends
on the method:

- **`balanceUnsealed` / `balanceSealed` / `makeTransfer`** → *plan-derived*, from an inert
  `BalancedPlan`: the wallet's inputs netted against its own change and outputs. This
  **includes the DUST fee** the transfer burns, so a `sum(|diff|)` cap sees the whole
  movement. For `makeTransfer` the plan is built before the gate — the outputs are
  **mock-proven** (proofs are fixed-size, so the fee is exact) and the balancing is planned
  against the wallet's synced UTXOs, so **no real proving happens before the gate**. After it,
  `authorize` proves the same outputs for real, checks that the result is the planned
  transaction apart from its proofs, and signs that plan: the coins and the fee the policy
  saw are the ones spent. A transfer the wallet cannot fund fails at planning, before the
  gate ever runs.
- **`makeIntent`** → *request-derived*, from the declared inputs (outflow) and self-outputs
  (inflow). A maker offer is deliberately imbalanced and **pays no fee** (the taker does), so
  the request already is the complete movement. Its coins are still picked before the gate: the
  plan syncs the wallet's coins and builds the offer, and `authorize` proves that offer, so the
  coins the policy allowed are the ones spent. Whole coins are spent and the excess returns to the
  maker, so they net to the request exactly. An offer the wallet cannot fund fails at planning.
- **`balanceSealedMerge`** (a fully-sealed maker completed by merging) → the taker's own half,
  request-derived like `makeIntent`, **plus the DUST fee the merge burns** (when `payFees` on a
  live-DUST chain). The fee covers the whole merged tx and the maker never pays, so it is sized
  against a **mock-proven taker complement** — fixed-size proofs give the exact fee with no real
  proving — and a DUST spend is folded in as a dust outflow, so a `sum(|diff|)` cap sees the burn.
  A registration of the taker's NIGHT burns none of its held DUST, and the NIGHT coin it draws on
  returns whole, so neither adds an effect; `chain_extra.fee` shows it. The taker's half (its
  coins) and that fee are decided before the gate, and `authorize` proves exactly them, so nothing
  is re-synced or re-priced in between.

Shielded value a dapp routes back to the wallet is netted in as well: the base offers'
outputs are trial-decrypted with the shielded viewing key and each recognized receipt is
keyed by the segment its offer executes in. Without it the list would only carry the wallet's own
balancing contribution, over-stating outflow — a conservative cap bound rather than the
wallet's true net. Recognizing a receipt needs no spend key.

There is deliberately **no flat, segment-summed view**. Summing the segments discards the
guaranteed-versus-fallible distinction, which is the whole point of what the seam hands a
policy: a fallible inflow must never be allowed to offset a guaranteed outflow. See
[Effect-aware policies](#effect-aware-policies-ows-policy-create) for how a policy is expected to read this, and for
the sibling `chain_extra.contracts` list that answers *who* the transaction talks to.

So a `makeTransfer` of `V` NIGHT to someone else nets to `-V` in NIGHT plus the DUST fee it
burns — the NIGHT matching the recipient's on-chain credit `+V` (change returns to self).
Verified against a real broadcast on preview: a 1,000,000-NIGHT transfer credited the recipient
exactly 1,000,000.

### The second policy pass in detail

`enforce_effect_policies` (`ows-lib/src/key_ops.rs`) is the gate `prepare_signable_tx`
runs at the plan→authorize seam. It fills the plan's context into the transaction context
under `chain_extra` — built whole by `ConnectorPlan::policy_context` in `ows-midnight`, which
`ows-lib` only hands on — leaving the flat `effects` field empty, since
the wallet can only account for its **own** movement, not the transaction's full effects —
and calls `evaluate_policies`, the same evaluation as the first pass. The declarative rules
run again, since planning can take minutes on a cold sync and a rule such as an expiry may
have lapsed meanwhile; the executable policies now see the effects. A denial returns a
`PolicyDenied` error, so the key is never used to prove anything.

This is what lets a policy express a rule like *"cap the summed movement at 1,000,000"* —
a rule that is impossible to enforce at the first pass, because the first pass sees empty
effects; the real movement is only known after planning. See [Effect-aware policies](#effect-aware-policies-ows-policy-create).

### How this differs from other chains

| | Other chains | Midnight |
|---|---|---|
| `--tx` input | hex unsigned tx bytes | **JSON** DApp Connector request |
| What signing produces | a signature | a fully **sealed** transaction (`SignResult.transaction`) |
| Who balances / pays fees | the caller | the **wallet** (fees in dust) |
| Proof | none | zero-knowledge proofs built at authorize time |
| Policy passes | one (request shape) | **two** (shape, then effects) |

### Validation

The connector methods need a local prover, a funded wallet and the indexer, so they run by hand
on preview: `e2e/dapp-connector-siblings.md` walks through each method, and
`e2e/midnight-connector-siblings.sh` drives them interactively. The second pass is covered by
`effect_policy_pass_gates_via_executable_policy` (`ows-lib/src/key_ops.rs`), which drives
`enforce_effect_policies` the way an executable program consumes it, and by the
`plan_segment_effects` cases in `ows-midnight/src/balance_tx.rs`.

## Sign and send (`ows sign send-tx`)

**Purpose:** take a DApp-connector request for a `midnight:<network>` wallet, balance it with the
wallet's own inputs, sign and prove it, seal it, and broadcast it to the node — the full
`sign → prove → seal → submit` pipeline behind one command.

```sh
OWS_PASSPHRASE="…" ows sign send-tx \
  --wallet demo --chain midnight:preview \
  --json --tx '<connector-request-json>'
```

On a `midnight:*` chain the `--tx` payload is a **DApp-connector request JSON** (not raw signed
bytes). The wallet reads it, funds/balances it against its own state, and submits the result. On
every other chain `send-tx` keeps its original meaning (sign hex bytes and broadcast).

As a shorthand, `--tx` also accepts a **bare** MIP-0005 `swapoffer…` bech32 offer or a **bare** hex
transaction directly, with no JSON envelope. The wallet normalizes it into the equivalent request: a
bare offer or a fully-sealed maker becomes `balanceSealedTransaction`, any other proven hex a
`balanceUnsealedTransaction` (`ows sign tx` accepts the same forms). A MIP-0006 offer payload is not
a request, so it is refused bare: pass its `offerBech32` instead, or the payload itself as
`makerTx` (below). A sealed transaction to broadcast as it is must be sent as a `submitTransaction`
request: bare, it is a maker offer to complete.

### The connector methods

The request is routed by its JSON `method` field:

- **`balanceUnsealedTransaction`** (also the default when `method` is absent, for backward
  compatibility) — the DApp hands over a proven, *unsealed* transaction with a deficit; the wallet
  balances it with its own inputs across all three value domains, then seals and submits.
- **`makeTransfer`** — the wallet *builds* the outputs (a deficit), balances them with its own inputs,
  and seals. The intent keys off a non-zero id; unshielded NIGHT movement rides that intent's
  fallible offer, so it executes in the intent's own fallible segment (a multi-UTXO move would
  overrun the guaranteed segment's tight `time_to_dismiss` budget), while shielded outputs ride
  the guaranteed segment.
- **`makeIntent`** — build an imbalanced *maker offer* (real inputs + declared wanted outputs), able
  to contribute shielded inputs with per-token whole-coin change returned to the maker's own keys.
- **`balanceSealedTransaction`** — the *taker* completes a maker offer. The offer is sealed, as the
  connector spec types this method's input, and its binding keeps it from being balanced, so the
  wallet completes it by merging its own complementary half onto it. A proven, unsealed transaction is
  refused here: `balanceUnsealedTransaction` balances one in place. The maker input (`makerTx`) is
  hex, a MIP-0005 `swapoffer…` bech32 string (either case), or a **MIP-0006** offer payload as an
  indexer serves it, passed as a JSON **string**:

  ```json
  {"method":"balanceSealedTransaction",
   "makerTx":"{\"version\":1,\"offerBech32\":\"swapoffer1…\",\"computed\":{\"gives\":[…],\"wants\":[…]}}"}
  ```

  The offer is authoritative: the wallet derives what it gives and wants from the transaction and
  refuses a payload whose `computed` terms don't match, a one-sided offer (one that gives without
  wanting, which MIP-0006 forbids a taker to settle), and a payload without `offerBech32`.

  Whatever its form, the offer must keep all its value in the guaranteed section (segment 0), as
  MIP-0006's swap offers do. The ledger commits segment 0 and then applies each fallible segment on
  its own, so a fallible segment can fail while the taker's payment in segment 0 stands. The wallet
  refuses a maker with shielded coins, unshielded inputs or outputs, or an imbalance in a fallible
  segment; a fallible contract call that moves no value is fine.
- **`submitTransaction`** — broadcast a transaction that is already sealed and balanced, such as the one
  `ows sign tx` returned, unchanged:

  ```json
  {"method":"submitTransaction","tx":"<hex of the sealed transaction>"}
  ```

  The wallet proves, signs and pays for nothing here, so it needs no key: in owner mode no passphrase
  is asked for and the wallet is never decrypted. It checks the transaction as every sealed submit is
  checked before it goes to the node: it must be sealed (`proof,pedersen-schnorr`; a proven, unsealed
  one is refused, since `balanceUnsealedTransaction` balances and seals it), parse whole, carry the
  chain's network id, and leave no segment short of any token. A maker offer, which a taker still has
  to complete, is short of what it wants, so it is refused with ledger error 138
  (`BalanceCheckOverspend`) before the node is contacted. The method has to be named: the wallet never
  infers a submit from the bytes. Because the bytes go out as they came in, a submit that timed out can
  be retried with the same transaction, which a re-run `send-tx` of the original request would not do:
  that plans a new transaction, possibly from other coins.

  Under an API token the submit still passes the token's policies, both passes, without the key ever
  being decrypted: the first over the request, the second with the `chain_extra` of a request that
  moves nothing (empty `segment_effects`, `contracts` and `dust_registrations`, `fee.mode` `none`),
  since whatever the transaction moves was authorized when it was sealed. A policy that should not let
  an agent relay transactions tells a submit apart by the request's `method`, in
  `transaction.raw_hex`. Its audit records are written as for any other `send-tx`. `ows sign tx`
  refuses a submit, which has nothing to sign.

Balancing brings every token back to zero in every segment, as the Midnight wallet SDK does: the
wallet adds inputs for whatever the transaction is short of, and an output to itself for any value no
output receives — its own change, a maker's surplus, or what a contract action left over. The ledger
rejects only a shortfall, so that value would otherwise be destroyed when the transaction is applied,
or, for NIGHT, fail the ledger's supply check.

An out-of-spec request (a proof-preimage input or a `ClaimRewards` mint claim) is rejected with a
**precise** error rather than a generic "unsupported". A dust registration the dapp put in the
transaction is signed only when it registers the wallet's own NIGHT to the wallet's own dust address.
One to any other dust address would hand the wallet's DUST generation away and a deregistration would
switch it off, so the balancer refuses both before anything is proven, and the signer refuses them
again. With `payFees: false` the registration must also allow no fee payment (`allow_fee_payment` 0):
the wallet folds its NIGHT inputs into the dapp's lowest intent, and an allowance there would pay the
dapp's fee out of the DUST those inputs have accrued. With `payFees: true` its allowance counts as the
wallet's DUST outflow, in segment 0. Every registration the wallet signs, the dapp's and its own fee
registration alike, is listed for the policy pass in `chain_extra.dust_registrations` (see
[How the wallet pays](#how-the-wallet-pays--chain_extrafee-and-chain_extradust_registrations)).

`ows sign tx` returns the fully sealed, proven Midnight transaction on `SignResult.transaction`
(`None` for other chains) — the seal-*without*-broadcast capability: the kind of bytes `send-tx`
broadcasts, surfaced through a command that never submits. A `submitTransaction` request to
`send-tx` broadcasts those exact bytes later.

### What it does

1. **Parse** the connector request and classify the method.
2. **Plan (inert).** Select the wallet's own inputs to cover the deficit — per intent, across
   unshielded Night, shielded Zswap, and dust — **without** building any spend witness. The
   plan carries only public selection data; no bearer instrument exists yet. This is the point a
   policy pass can gate on the plan's key-derived effects (the `prepare_signable_tx` seam).
3. **Authorize (past the seam).** Inside `ows-signer`, build and prove the shielded/dust spend
   preimages, sign the unshielded intent (detached BIP-340), and fold the proven sections back in.
   The spend witness is born and consumed behind the key boundary and never reaches the balancer.
4. **Seal** the proven, signed transaction.
5. **Submit** the sealed bytes to the node over its Substrate RPC and print the resulting tx hash.

### End-to-end on preview and preprod

`e2e/midnight-sign-send-tx.sh` exercises this command against a live node, preview by default
(`CHAIN=midnight:preprod` for preprod). It builds `ows` from the checkout, confirms the command is
wired, and checks that a malformed request is rejected with a precise error (all offline); then it runs
the live path in two steps — **seal** the request with `sign tx` (no broadcast, printing the sealed
tx), then **submit** it with `sign send-tx`. A DApp normally supplies the proven (`proof,embedded-fr`)
input; the checkout bundles one per network at `e2e/shielded-movement-cap/tx-proven-preview.hex` and
`tx-proven-preprod.hex`, so the live run works out of the box (override it with `TX_JSON=<path>`). Each
maker is input-free, so each run re-selects fresh wallet inputs and is reusable.

Real round-trips landed on preprod at
`0x379f10efcd2b82bac2c5e281d2d175b0367aef195b8845cdb75388737632fed3` (block 1762181) and on preview at
`0xbb1753c3503c845881e998034138fa98817cc6f90a80cb9d62c2074ae9d63c3c` (block 1423263), crediting the
wallet's own address with the balanced outputs.

### The three value domains

- **Unshielded (Night).** Balanced from the wallet's UTXO set; authorized with a detached BIP-340
  intent signature.
- **Shielded (Zswap).** Balanced from the wallet's own synced coins (whole-coin selection, self-change
  to the wallet's keys); each spend witness is built and proved inside the signer via the crypto
  provider.
- **Dust (fees).** The fee is sized against the node's real fee gate. Whether a dust registration is
  added is decided at run time by a `dust_ledger_is_live` probe against the indexer (see
  [Fund balance](#fund-balance-ows-fund-balance)), not a compiled-in flag; fees are paid with a generationless
  registration or a proof-bearing spend when NIGHT is fully registered. By default (`payFees: true`)
  the wallet pays the fee; if the probe can't confirm the dust ledger is live it errors rather than
  emit a fee-less tx the node would reject — pass `payFees: false` to opt out on a genuinely fee-less
  network.

### The credential

`OWS_PASSPHRASE` carries either the **owner envelope passphrase** (decrypts the packed `MNK1` role
seeds and builds the `MidnightCryptoProvider`) or an **api-key token**, which runs both policy
passes exactly as `sign tx` does: the request's shape before the key is decrypted, then the planned
effects, the wallet's own inputs, change and DUST fee included, before anything is proved or
broadcast. All bearer key material stays in `ows-signer`; `ows-midnight` holds none,
not even while sizing the fee, where the signer hands it mock-proven sections rather than the
key-bearing preimages (enforced by the `no_key_material_gate` workspace test).

### Node RPC

Submission talks to the Substrate node RPC, resolved **separately from the balance indexer**. Provide
it with `--rpc-url <url>`, else it resolves from the vault's config (`~/.ows/config.json` for the
CLI, see [Which config file](#which-config-file)) under `rpc["midnight:<network>:node"]`. Only preview ships a default; for mainnet and preprod, set it
yourself, to a hosted endpoint from the same networks guide or to your own node. A plaintext
`http://` or `ws://` URL is accepted only for a loopback address, such as a local node; anything else
needs `https://` or `wss://`. Credentials in the URL never appear in error messages. Each node call
is bounded (connect 30s, request 60s), and a failed or timed-out submit names the transaction hash,
since the node may have accepted it: check whether it landed before retrying.

### Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; required to build the provider that signs/proves. A `submitTransaction` needs no passphrase; under a token it runs the token's policies. |
| `OWS_WALLET` | Default for `--wallet`. |

### The code path

- CLI: `commands/send_transaction.rs` → `ows_lib::sign_and_send` (token) / `sign_encode_and_broadcast`
  (owner); Midnight routes through `decode_tx_input` → `prepare_signable_tx` (the plan/authorize seam).
- Balancing + seam: `ows-midnight/src/balance_tx.rs` (`plan_unsealed_proven_tx`, `authorize_proven_tx`),
  `balance_tx/fee_sizing.rs`, `dapp_connector/{mod,balance_unsealed}.rs`, `prover.rs`.
- Authorization (bearer instruments): `ows-signer/src/chains/midnight.rs`
  (`authorize_shielded`, `authorize_dust`, `sign_proven_intent`, `seal_signed_proven`).
- Submission: `ows-midnight/src/submit.rs`; node RPC config in `ows-core/src/config.rs`. A
  `submitTransaction` is checked in `dapp_connector/submit_transaction.rs` (`connector_submission`)
  and relayed by `sign_and_send` / `submit_midnight_transaction` (`ows-lib/src/ops.rs`) with no key.

## Message signing (`ows sign message`)

**Purpose:** sign an arbitrary message for a `midnight:<network>` wallet with its **unshielded**
(Night) key, producing a detached signature — the Midnight arm of the cross-chain `ows sign message`.

```sh
OWS_PASSPHRASE="…" ows sign message \
  --wallet demo --chain midnight:preview --message "hello world"
```

### What it signs with

Midnight message signing uses the wallet's **unshielded** signing key (the same key that authorizes
unshielded intents), derived inside `ows-signer`'s `MidnightCryptoProvider` from the packed `MNK1`
role seeds. The shielded and dust keys are not involved. As with every Midnight key operation, the
bearer key material never leaves `ows-signer`; the CLI and `ows-midnight` only ever see the resulting
signature.

### What it signs

The message is framed as the DApp Connector specification requires for `signData`, byte for byte as
MIP-0031 pins it: the ASCII prefix `midnight_signed_message:`, the message's length in bytes in
decimal, a `:`, then the message bytes. The signature is BIP-340 over the SHA-256 of that frame, so
a verifier rebuilds the frame from the message it asked for. The frame is what keeps a message
signature from doubling as a transaction signature: the ledger checks intent inputs and dust
registrations with this same key, over SHA-256 of a `data_to_sign` that never starts with the
prefix.

### What it returns

One hex string of 96 bytes (192 hex characters): the signer's 32-byte x-only BIP-340 public key,
then the 64-byte BIP-340 signature (`bytes(R) ‖ bytes(s)`). `--json` prints the same string as
`signature`, with `recovery_id` `null`: a BIP-340 signature does not recover its key, which is why
the key comes with it. For `hello world` from the BIP-39 test wallet, printed as one line and shown
here split:

```
# public key (32 bytes)
c76a7f2b975d39e6d8af0e285b6805260031efeced12f17f7c7015bb13a6089c
# signature (64 bytes)
153af226d0b0a94ef5ac2de3fdca33d500d544bc536a8b2b97e5fcc2ca2fe2e592ed7c2ae1e1eb00d9620750058fe93b75caa100251269de94a5270455cfcb9b
```

A verifier splits it at byte 32, rebuilds MIP-0031's frame from the message it asked to have signed,
and checks the signature with BIP-340, the 32-byte SHA-256 of the frame being BIP-340's message:

```python
out = bytes.fromhex(signature_hex)
verifying_key, signature = out[:32], out[32:]
frame = b"midnight_signed_message:%d:" % len(message) + message   # message: the bytes signed
assert bip340_verify(verifying_key, hashlib.sha256(frame).digest(), signature)
```

In the connector's `Signature` terms the two halves are `verifyingKey` and `signature`, and the
scheme is `schnorr_bip340`; OWS returns them joined rather than as MIP-0031's separate fields. A
valid signature proves only that the holder of that key signed: to attribute it to a wallet, also
check the key against the unshielded address you expect, which derives from it.

The output is the same on every network. The frame names no network and the key is the same, and
the signature is deterministic (BIP-340 with all-zero auxiliary randomness), so one message signed
on preview and on mainnet gives the same 192 hex characters. A signature made on preview is
therefore just as valid for the wallet's mainnet address. A policy that allows message signing only
on `midnight:preview` limits which command runs, not where its signatures can be used; give an agent
message signing only where any network's verifier may see the result.

Raw hash signing (`sign_hash` in `ows-lib`, `signHash` in the bindings) is refused for Midnight.
Nothing on Midnight signs a caller-supplied digest, and a raw signature with this key could authorize
a spend.

### The credential

`OWS_PASSPHRASE` carries the **owner envelope passphrase** or an **api-key token**, resolved before
signing. A token's policies are checked against the message request before the key is decrypted, as
on every other chain; a message has no effects for a policy to inspect. Without a credential the
provider can't be built and the command errors (there is nothing public to sign with).

### Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; required to build the signing provider. |
| `OWS_WALLET` | Default for `--wallet`. |

### The code path

- CLI: `commands/sign_message.rs` → resolves the credential and calls the signer.
- Signing: `ows-signer/src/chains/midnight.rs` (`signed_message_bytes` frames the message,
  `sign_unshielded_message` signs it with the provider's unshielded key). The per-network id /
  address HRPs come from `MidnightNetwork`.

## Effect-aware policies (`ows policy create`)

**Purpose:** register a policy (from a JSON file) that a minted API key can enforce.

```sh
ows policy create --file /tmp/policy.json
```

`policy create` itself is generic — it stores a `Policy` JSON. What Midnight adds is a
*reason* to write an **executable** policy that reads a transaction's wallet-relative
effects, because only an executable policy can read them.

### Two kinds of policy, two passes

A Midnight `sign tx` on the agent path is gated **twice** (see [Sign and seal](#sign-and-seal-ows-sign-tx)),
and every policy on the key runs both times:

1. **First pass**, over the request's *shape*. The transaction has not been planned yet, so
   there is no movement to see: `effects` is empty and `chain_extra` is absent. Declarative
   rules such as `AllowedChains` and `ExpiresAt` decide here; executables run too.
2. **Second pass**, over the transaction's *effects*. After the wallet plans the balancing,
   the plan's key-derived, wallet-relative effects are filled in **per execution segment**
   under `chain_extra`, and every policy runs again. The declarative rules are re-checked,
   since planning can outlast an expiry, and the executables decide on the movement.

So an executable policy sees each Midnight transaction **twice**: once without `chain_extra`,
then with it. Tell the passes apart by what the request **is**, never by a missing field:
`chain_extra` is just as absent for a Midnight `sign message`, for a balance read, and for every
other chain the same wallet can sign for, and a token is scoped to a wallet, not to a chain
family. So allow the first pass only for `request_type == "sign_transaction"` on a `midnight:`
chain, decide on the second, and deny every other request type and chain unless you mean the
token to have it. To fail closed, also deny inside the second pass when its `segment_effects`
don't parse.

The Midnight effects are handed to the program under **`transaction.chain_extra`**, not the
generic `transaction.effects` field. That field would imply a full account of *all* a
transaction's effects; the wallet can only account for its **own** movement, per segment, so
it leaves `effects` empty and populates `chain_extra` instead.

So a policy that needs to reason about *how much value moves* must be **executable** — a
program that reads `transaction.chain_extra.segment_effects` from the policy context. A
purely declarative rule can never see the movement, because the movement is unknown until
after planning.

> **⚠ Deploy footgun — declarative-only keys don't cap movement.** Declarative rules can't
> read `chain_extra`. So a key whose policies carry *only* declarative rules (`AllowedChains`,
> expiry, …) passes the second pass whenever it passed the first — it moves unlimited value at
> the seam. Shape rules gate
> *which* transactions may be signed; **only an executable effect policy caps how much they
> move.** Don't ship an agent key with shape rules only and assume movement is bounded.

### Anatomy of an effect-aware executable policy

The policy JSON points `executable` at a program (any language) that reads the policy
context on stdin and prints an `{allow, reason}` verdict. The effects are under
`transaction.chain_extra.segment_effects`, one entry **per execution segment** —
`{segment, effects:[{address, diff:[[token, delta], …]}]}`, each domain effect keyed by the
wallet's own address. Each `delta` is a signed decimal **string**, as in every chain's
effects, so parse it before doing arithmetic on it (a JSON number would lose precision past
2^53). `segment == 0` is the guaranteed segment, always executed and pooled
across every intent in the transaction; anything non-zero is one intent's fallible half,
allowed to fail on its own (see
[Intents and segments](#intents-and-segments-are-not-the-same-thing)). Cap outflows in **every**
segment: a fallible segment normally executes, it only *may* fail, and `makeTransfer` itself sends
its NIGHT in segment 1. Only an inflow in a fallible segment is uncertain, so never let one offset
an outflow. Summing the absolute movement over all segments, as below, is the simple conservative
form:

```python
#!/usr/bin/python3 -I
import sys, json
ctx = json.load(sys.stdin)
midnight = ctx["chain_id"].startswith("midnight:")
signing = ctx["request_type"] == "sign_transaction"
extra = (ctx.get("transaction") or {}).get("chain_extra")
def verdict(allow, reason):
    print(json.dumps({"allow": allow, "reason": reason}))
    sys.exit()
if midnight and ctx["request_type"] == "read_balance":  # unseals the key to read balances; signs nothing
    verdict(True, "balance read")
if not (midnight and signing):
    verdict(False, f"{ctx['request_type']} on {ctx['chain_id']} is not what this key is for")
if extra is None:  # a Midnight transaction's first pass: nothing planned yet, the second decides
    verdict(True, "first pass")
segs = extra.get("segment_effects", [])
total = sum(abs(int(d)) for s in segs for e in s.get("effects", []) for _, d in e.get("diff", []))
verdict(total <= 1_000_000, f"summed movement {total} (cap 1000000)")
```

> **⚠ A fallible segment id is an identifier, not a sequence number.** It is the id of the
> intent whose fallible half runs there, whatever `u16` that transaction's author picked — a
> real preprod transaction carries intents at ids 2260 and 15441, not 1 and 2. Never assume
> small or contiguous ids, and never read one as a position: test guaranteed-versus-fallible
> as `segment == 0` versus `segment != 0`.

Registered as a policy that `deny`s on failure, with the chain allowlist as a declarative rule
too:

```json
{ "id": "midnight-move-cap", "name": "Midnight movement cap", "version": 1,
  "created_at": "2026-07-15T00:00:00Z",
  "rules": [{ "type": "allowed_chains", "chain_ids": ["midnight:preprod"] }],
  "executable": "/home/you/.ows/plugins/policies/midnight-move-cap.py", "action": "deny" }
```

Then minted into a key (`ows key create … --policy midnight-move-cap`, see
[API keys](#api-keys-ows-key-create)). When the agent runs `sign tx`, the second pass hands
this program the real effects and it caps the movement — a cap that fires **before** any
proving, so a denied transaction costs no prover work.

### Who the transaction talks to — `chain_extra.contracts`

`segment_effects` answers *how much the wallet moves*, and deliberately nothing else: no
counterparty, no provenance. The counterparty lives in its own sibling key,
**`transaction.chain_extra.contracts`** — one entry per contract action the transaction
performs, so a policy can gate on *who* as well as *how much*:

```json
{ "segment": 0,
  "kind": "call",
  "address": "9f3c…",
  "entry_point": "swap",
  "sent_to":       [["0000…", "1000"]],
  "received_from": [["a71b…", "25"]],
  "payouts": [{ "token": "a71b…", "amount": "25", "recipient": "3e08…",
                "recipient_kind": "user", "to_wallet": true }] }
```

- **`segment`** — the segment this action executes in, same convention as the effects: `0`
  guaranteed, non-zero fallible (the carrying intent's id). One call carried by one intent can
  declare both a guaranteed and a fallible transcript, and then appears **twice** — once per
  transcript, each at the segment that transcript runs in — so a record is read on its own
  rather than by where it sits in the list. Entry count tracks transcripts, not intents.
- **`kind`** — `call`, `deploy`, or `maintain`. Only a `call` names an `entry_point`; a
  deploy or a maintenance update declares no value movement, so its amounts are empty.
- **`sent_to` / `received_from`** — per token, the **total** value the contract's transcript
  declares it takes in and pays out, as a decimal string like the effects' deltas. The names are
  kept for compatibility, but neither is the wallet's own: `sent_to` is what every party to the
  transaction pays the contract together, and `received_from` is what the contract pays out to
  every recipient together, the wallet or not.
- **`payouts`** — who `received_from` goes to: one entry per token and recipient the call's
  transcript declares an unshielded payout to, with the recipient's hex address (a user's address
  hash, or a contract's address), `recipient_kind` (`user` or `contract`) and `to_wallet`, whether
  the recipient is the wallet's own unshielded address. A deploy or a maintenance update has none.
  Mints and shielded transfers a call declares are not reported here.

Only the `balance*` methods can carry contract actions — they complete a transaction someone
else authored. `makeTransfer` and `makeIntent` build the wallet's own transfer from the
request alone, so their `contracts` is always empty.

> **⚠ The amounts are contract-*declared*, not proven wallet movement.** They are what the
> transcript says the contract takes in and pays out, so they equal what *the wallet* sends
> and receives only when the wallet is that contract's sole counterparty in the segment — the
> normal shape for a wallet-authored connector transaction, but not a guarantee. For what the
> wallet actually moves, cap on `segment_effects`; use `contracts` to decide **whether to
> deal with this counterparty at all** (an address allow-list, an entry-point allow-list),
> not as a second opinion on the amounts. A "fair swap" rule that allows a call because its
> `received_from` covers its `sent_to` would allow one that pays everything to a third party:
> if a rule must reason about a payout, read the `payouts` with `to_wallet`.

```python
#!/usr/bin/env python3
import sys, json
ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
called = {c["address"] for c in extra.get("contracts", []) if c["kind"] == "call"}
unknown = called - {"9f3c…"}
print(json.dumps({"allow": not unknown,
                  "reason": f"unapproved contracts: {sorted(unknown)}"}))
```

### How the wallet pays — `chain_extra.fee` and `chain_extra.dust_registrations`

`segment_effects` counts the DUST a fee *spends* out of what the wallet holds. A generationless
registration spends none of it: it pays from DUST the wallet's unregistered NIGHT has accrued but
not yet been credited with, so it shows nothing there. It still pays the fee, and it points where
that NIGHT generates DUST. Two sibling keys show both:

```json
"fee": { "mode": "registration", "dust_burned": "60000" },
"dust_registrations": [
  { "intent_id": 4,
    "carried": false,
    "night_address": "mn_addr_preview1…",
    "dust_address": "mn_dust_preview1…",
    "own": true,
    "allow_fee_payment": "60000",
    "replaces_delegation": null }
]
```

- **`fee.mode`** — how the wallet pays the fee: `spend` (a proof-bearing spend of DUST it holds),
  `registration` (a generationless registration of its unregistered NIGHT, listed in
  `dust_registrations`), or `none` (no fee section: `payFees: false`, or a `makeIntent` maker
  offer, which the taker pays for).
- **`fee.dust_burned`** — the most DUST the fee can take, as a decimal string. A spend takes
  exactly this, and `segment_effects` shows it as a `dust` outflow in segment 0. A registration
  takes at most its `allow_fee_payment`, which the ledger draws from the generationless DUST of
  the NIGHT it registers; whatever the fee leaves is credited to the wallet's DUST address. To cap
  what fees cost in DUST whichever way they are paid, cap `fee.dust_burned`.
- **`dust_registrations`** — every dust registration the wallet signs, by intent: its own fee
  registration (`carried: false`), which rides its balancing intent (in a `balanceSealedTransaction`,
  the taker's complement intent), and any the dapp's transaction carries into
  `balanceUnsealedTransaction` (`carried: true`). Each points the wallet's NIGHT key
  (`night_address`) at a DUST address (`dust_address`); `own` says whether that address is the
  wallet's, and is always `true`, since the wallet refuses to sign a registration to any other, or a
  deregistration. Dust actions apply before any segment executes, whichever intent carries them, so
  an entry names its intent (`intent_id`), not a segment.
- **`allow_fee_payment`** — how much of the fee the registration may pay from the generationless
  DUST of its intent's NIGHT. A carried registration must allow `0` with `payFees: false`; with
  `payFees: true` its allowance is also counted in `segment_effects`, as a `dust` outflow in
  segment 0, on top of whatever the wallet's own fee section burns.
- **`replaces_delegation`** — whether the registration moves an existing delegation of that NIGHT
  key to a different DUST address. On chain a registration overwrites the key's delegation, and a
  key delegated elsewhere can still hold NIGHT coins that generate nothing (those it held before
  the delegation), which is exactly when the wallet picks the registration path. The indexer
  reports whether a NIGHT coin generates DUST, not where its key is delegated, so the wallet
  cannot tell: the field is always `null` (unknown) today. Where the wallet's NIGHT may be
  delegated to another DUST address, deny any transaction with a non-empty `dust_registrations`.
  The wallet prefers a registration whenever it holds an unregistered NIGHT coin, so such a policy
  refuses those transactions rather than moving them to a spend.

```python
fee = extra.get("fee") or {}
if int(fee.get("dust_burned", "0")) > 1_000_000_000:
    verdict(False, f"fee may burn {fee['dust_burned']} DUST specks")
if extra.get("dust_registrations"):
    verdict(False, "registers NIGHT for DUST generation")
```

### How long a maker offer stands — `chain_extra.offer`

A `makeIntent` seals an offer that anyone holding it can complete until it expires, and the maker
can withdraw it only by spending one of its inputs, so its lifetime is authority the wallet hands
out. Its context carries the offer, which no other method has:

```json
"offer": { "intent_id": 1, "ttl": 1785878998, "ttl_is_default": true }
```

- **`intent_id`** — the intent the maker's offer keys at: the request's `intentId`, the id drawn
  for `"random"`, or `1` when the request names none.
- **`ttl`** — when the offer expires, in Unix seconds: the request's `options.ttl`, or the wallet
  default (`global_ttl` past now, currently an hour) fixed when the offer is planned. It is the
  instant that gets sealed.
- **`ttl_is_default`** — `true` when the request named no `ttl`.

```python
import time
offer = extra.get("offer")
if offer and offer["ttl"] - int(time.time()) > 300:
    verdict(False, f"maker offer stands until {offer['ttl']}, more than 5 minutes")
```

### Why the design consumes an executable policy rather than a built-in rule

An earlier iteration added a built-in `MovementLimits` rule to the core policy set. That
was **dropped**: baking a movement cap into the engine forces every consumer to accept one
fixed notion of "movement", and Midnight effects are richer than a single scalar
(per-domain, per-token, signed). Leaving the consumer as an **executable** policy keeps the
engine agnostic — a deployment expresses whatever cap, per-token limit, or allow-list it
wants as a program, and the engine's only job is to supply the effects and honor the
verdict.

### How this differs from other chains

Every chain can attach declarative rules and executable policies. The Midnight-specific
part is the **second pass**: only Midnight derives wallet-relative effects *after* planning
and re-runs the key's policies with them. On other chains, a transaction's effect is
knowable at the first pass, so there is nothing to re-evaluate.

### Validation

- **Unit:** `effect_policy_pass_gates_via_executable_policy` (`ows-lib/src/key_ops.rs`)
  drives `enforce_effect_policies` over a constructed `chain_extra` the way the executable
  programs consume `transaction.chain_extra.segment_effects`, and
  `effect_policy_pass_rechecks_declarative_rules` checks that an expired policy still denies
  there; `plan_segment_effects` cases in
  `ows-midnight/src/balance_tx.rs` cover the per-segment effect derivation, and
  `contract_interactions` cases in `ows-midnight/src/contracts.rs` cover the per-segment
  `contracts` derivation.
- **Real chain bytes:** `a_real_preprod_contract_call_is_read_from_the_chain_bytes`
  (`ows-midnight/src/contracts.rs`) extracts `contracts` from a settled preprod
  `addUnshieldedLiquidity` call and cross-checks the address and entry point against what the
  indexer independently reports for that transaction.

## API keys (`ows key create`)

**Purpose:** mint an API token (`ows_key_…`) that an autonomous agent uses in place of the
owner passphrase, scoped to specific wallets and policies.

```sh
ows key create --name midnight-agent --wallet length-wallet --policy midnight-move-cap
# → ows_key_a126…            (printed once; store it)
```

`key create` is generic, but it is the linchpin of Midnight's **agent** model: every
Midnight command that needs the key accepts *either* the owner passphrase *or* a token in
`OWS_PASSPHRASE`, and the token is what turns on policy enforcement.

### Owner vs token — one env var, two meanings

`OWS_PASSPHRASE` is inspected by prefix (`key_store::TOKEN_PREFIX` = `ows_key_`):

- **No `ows_key_` prefix** → treated as the **owner envelope passphrase**. Decrypts the
  stored mnemonic with scrypt. Full authority, no policy gate. (Imported wallets use an
  empty passphrase, so owner unlock is literally `OWS_PASSPHRASE=`.)
- **`ows_key_` prefix** → treated as an **API token**. The key is looked up by token hash,
  the token's expiry and wallet-scope are checked (`load_authorized_wallet`), policies are
  evaluated, and only on allow is the key decrypted (via HKDF). This is the agent path.

Both converge on the same packed Midnight key and the same downstream code — only
credential resolution and policy-gating differ.

### Where the token matters for Midnight

#### `fund balance`

A token routes balance reads through the policy-enforcing channel
(`enforce_policies_and_decrypt_key`) rather than the raw envelope decrypt. Balance has no
transaction to bind spending policies against, so here the token proves *access* — it lets
an agent read shielded/dust balances without holding the owner passphrase. A bad or
unknown token fails cleanly (`error: API key not found`, exit 1, no panic). A no-policy token
yields the full balance. Each token read writes a `read_balance` audit record, `outcome=allowed`
or `outcome=denied` with the denying policy, as signing does, so an agent probing its policy
through balance reads leaves a trail.

#### `sign tx`

A token turns on **both** policy passes for the connector pipeline
(see [Sign and seal](#sign-and-seal-ows-sign-tx)):

1. the first pass gates the request shape,
2. the second, effect-aware pass gates the wallet-relative movement (executable policies),
   and re-checks the declarative rules.

Attach the effect-aware policy at mint time with `--policy <id>` (see
[Effect-aware policies](#effect-aware-policies-ows-policy-create)); the token then enforces it on every `sign tx`.

> **⚠ A declarative-only token does not cap movement.** Declarative rules can't read the
> effects. A token whose policies carry *only* declarative rules (`AllowedChains`, expiry, …)
> passes the second pass whenever it passed the first — it gates *which*
> transactions may be signed, not *how much they move*. To bound value, the token must carry
> an **executable** effect policy; minted with shape rules only, it lets the agent move
> unlimited value on Midnight.

### Scope and lifecycle

- `--wallet` is repeatable — a token is scoped to the wallet ids it is minted for, and
  `load_authorized_wallet` rejects use against any other wallet.
- `--policy` is repeatable — attach one or more policy ids.
- `--expires-at` sets an optional ISO-8601 expiry, checked on every use.
- `ows key list` shows the keys (never the tokens); `ows key revoke --id <id> --confirm`
  removes one.

### How this differs from other chains

The token machinery is chain-agnostic. The Midnight-specific consequences are the two
places above — token-routed balance reads across three domains, and the **two-pass**
policy enforcement on the connector `sign tx` path (only Midnight has a second,
effect-aware pass).

### Validation

- **Balance:** `e2e/midnight-fund-balance.sh` mints a token for the wallet and runs the balance
  in owner and token mode side by side.
- **Signing:** `effect_policy_pass_gates_via_executable_policy` (`ows-lib/src/key_ops.rs`) runs
  the second, effect-aware pass over a token's executable policy.

## Endpoints (`ows config show`)

**Purpose:** show the vault path and the configured RPC endpoints, including Midnight's.

```sh
ows config show
# …
# RPC endpoints:
#   midnight:preview         https://indexer.preview.midnight.network/api/v4/graphql  (default)
#   midnight:preview:node    https://rpc.preview.midnight.network/                    (default)
#   midnight:preview:prover  http://127.0.0.1:6300                                    (custom)
```

`config show` is generic, but Midnight is the one chain family that registers **two
endpoints per network** (indexer + node), with an optional third for proving, and
understanding why is central to how Midnight commands reach the network.

Only preview ships a default indexer: mainnet and preprod have no public indexer that answers
without an API key, so their `midnight:<net>` entry has to be set (see
[Fund balance](#fund-balance-ows-fund-balance)). The same goes for their `midnight:<net>:node`
entry: only preview ships a default node, and Midnight's
[networks guide](https://docs.midnight.network/guides/networks-and-environments) lists the hosted
mainnet and preprod endpoints, which take a `?project_id=` key.

The sample above shows a custom `:prover` entry. That key is **not** shipped in defaults, so
it appears in `config show` only after you add it to `~/.ows/config.json`.

### Endpoints per network: indexer, node, and optional prover

Midnight splits its read and write paths across different services:

- **`midnight:<net>` → the GraphQL indexer.** Used by [`fund balance`](#fund-balance-ows-fund-balance)
  to read unshielded UTXOs, replay the shielded (`zswapLedgerEvents`) and dust ledgers, and
  read the current block height for the snapshot fast-path. `resolve_indexer_url` looks up
  this key.
- **`midnight:<net>:node` → the Substrate node.** Used by
  [`sign send-tx`](#sign-and-send-ows-sign-send-tx) to broadcast a sealed transaction
  (`Midnight::send_mn_transaction`). `resolve_midnight_node_rpc_url` looks up the
  `{chain_id}:node` key.
- **`midnight:<net>:prover` → an optional proof server** (HTTP, default port 6300). When
  set, authorize / prove paths post `/check` and `/prove` to that URL. When absent or blank,
  OWS proves in-process with the local zkir prover (circuit keys under
  `~/.ows/chains/midnight/proving-keys`). There is no shipped default — local proving remains
  the default. Example override in `~/.ows/config.json`:

```json
{
  "rpc": {
    "midnight:preview:prover": "http://127.0.0.1:6300"
  }
}
```

Remote proving sends each proof's preimage to the configured host, and a spend's preimage
carries the key that authorizes it: the wallet's **coin secret key** for a shielded spend, which
can spend every shielded coin the wallet holds, and its **dust secret key** for a DUST spend,
which can burn its DUST as fees. The unshielded key, which controls NIGHT and other unshielded
tokens, never leaves the signer. Only point `:prover` at a proof server you trust as much as the
wallet itself, and prefer a local instance (`http://127.0.0.1:6300`). A plaintext `http://` URL
is accepted only for a loopback address; anything else needs `https://`. Credentials in the URL
never appear in error messages. Requests to the proof server ignore `HTTP_PROXY` and `ALL_PROXY`
and follow no redirect, so whatever runs `ows` cannot divert the keys by setting the environment.
A loopback port is still no proof of identity: any local process can listen on `127.0.0.1:6300`
while the proof server is down, so on a machine shared with an agent, keep a local proof server
running or leave `:prover` unset and prove in-process.

Indexer and node are resolved by **separate** functions on purpose. Both are exact lookups on
their key — `resolve_indexer_url` on `midnight:<net>`, `resolve_midnight_node_rpc_url` on
`midnight:<net>:node` — and node resolution deliberately has **no namespace fallback**: a
missing `:node` entry errors with a clear message rather than silently sending a broadcast
to the indexer URL. An explicit `--rpc-url` overrides the node lookup. Each resolver's
error names the exact config key to set, so a missing endpoint is self-explaining. The
optional `:prover` key is likewise an exact lookup (`resolve_midnight_prover_url`); missing
means local proving, not an error.

### Overriding endpoints

`config show` annotates each endpoint `(default)` or `(custom)`. A custom
`~/.ows/config.json` can point any of these keys at a private indexer, node, or proof server
(e.g. for a feature testnet whose reference isn't a shipped default). Because a Midnight
network is identified by its **verbatim CAIP-2 reference**, an ad-hoc `midnight:feature-x`
network addresses and signs correctly out of the box — you only need to add
`midnight:feature-x` and `midnight:feature-x:node` entries so its indexer and node can be
reached (and optionally `midnight:feature-x:prover` for a remote proof server).

### Which config file

The indexer, the node and the proof server come from the config of the vault the call runs against,
and the snapshot caches and proving keys live under that vault. For the CLI that is `~/.ows`. A caller
that names its own vault (the Node or Python bindings, or ows-lib with an explicit `vault_path`) gets
`{vault}/config.json` and `{vault}/chains/midnight/…`, so a `:prover`, `:node` or indexer entry in the
process's `~/.ows/config.json` cannot reach a signing or sending call made against another vault.

### How this differs from other chains

Other chain families register one RPC endpoint per network. Midnight registers two — a read endpoint (indexer) and a write endpoint (node) — reflecting its split
read/write architecture, plus an optional prove endpoint. The commands resolve them through
different code paths so they are never confused.

### Validation

Endpoint resolution is covered by unit tests in `ows-core/src/config.rs`
(`rpc_url("midnight:preview")` → the indexer URL; `rpc_url("midnight:preview:node")` → the
node URL). End to end, `e2e/midnight-fund-balance.sh` reads through the indexer and
`e2e/midnight-sign-send-tx.sh` broadcasts through the node.
