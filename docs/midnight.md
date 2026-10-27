# Midnight Support

> Non-normative reference for Midnight in the OWS reference implementation: network
> identifiers, the wallet account, and what each `ows` command does on a `midnight:*` chain.

Midnight is unlike the other chains OWS supports: a single wallet holds value in **three
independent domains** — unshielded (Night), shielded (Zswap), and dust (fees) — each with its
own key and address. That difference reaches most commands, so this page goes command by
command: the code path, the reasoning behind it, and how it differs from the other chains.

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
derived too (`MidnightSigner::derive_addresses`) and printed by `ows fund balance` (see
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
`mn_shield-addr_preview`, `mn_dust_preview`, …). The wallet account and `derive` expose only the
unshielded one; `ows fund balance` prints the shielded and dust ones.

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
ows mnemonic derive --chain midnight:preview --index 1
# → mn_addr_preview14vxp6lccnpxc2zecz5a7fls8cc63kme540jwgajrakhmvc9xkxmqpmzrx8
```

Two things to notice. The mainnet address matches the `midnight_derive_addresses_mainnet_vector`
unit vector exactly. And across mainnet / preview / preprod / feature-x the Bech32m *data*
part is identical (`dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q`) — only the HRP and
its checksum change. One key, one hash; the network id lives in the human-readable prefix.

### What it prints

`ows mnemonic derive --chain midnight:*` prints **only the unshielded (Night) address**.
It does not print the shielded or dust addresses. This is deliberate: `derive` is the
generic one-address-per-chain command shared with EVM, Solana, Bitcoin, etc., and every
other chain has exactly one address. Midnight's shielded and dust addresses only surface
together, in a command that shows all three at once.

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
m/44'/2400'/0'/{role}/{index}
                ^role: 0 = unshielded (Night), 2 = dust, 3 = shielded (Zswap)
```

- **SLIP-44 coin type `2400`** identifies Midnight.
- **Account `0'`** is fixed — OWS is single-address-per-wallet, so per-address selection
  is the address `index`, not the account.
- The three **roles** produce the three independent domain seeds.

`derive` prints only the unshielded (role 0) address, but — because address derivation
routes every chain through the bundle — it assembles the full three-seed `MNK1` bundle and
`derive_address` extracts role 0 from it. That same packed bundle is what the shielded and
dust operations use to *act* in those domains — see
[the packed signing key](#the-packed-signing-key-and-why-it-is-mnemonic-only).

The role constants and path builder live in one place (`MidnightSigner::derivation_path`
/ `role_from_path`) so the coin type and account are a single source of truth, and a
derived key can be mapped *back* to its role when the bundle is decoded.

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
to **stderr**, so balances pipe out cleanly. A Preview run (values illustrative):

```
[ows-midnight] syncing balances from indexer (may take a while on first run)…
Addresses:
  Unshielded: mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms
  Shielded:   mn_shield-addr_preview1…
  Dust:       mn_dust_preview1…

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
shielded/dust when a key is available (else `(unavailable)`). Unshielded token types are the
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

The keys are unsealed at the account's stored index (the last segment of its derivation path), so
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
means an active ledger (shown); a missing, empty, or unreachable stream hides it. So dust appears
wherever the ledger is active — Preview/Preprod today, **mainnet automatically once its ledger
goes live**, no OWS change. The probe needs no wallet key (the tip is chain-global) and fails safe.

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
indexer (for example `http://localhost:8088/api/v4/graphql`). Credentials in the URL (user info,
query) never appear in error messages and are left out of the snapshot cache key, so rotating a
key keeps the snapshots, while switching to another indexer starts a fresh sync. Sync timeouts
(HTTP 30s, WS connect 30s, WS idle 90s, stall 120s) are fixed, not environment-configurable.

### Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; unlocks shielded/dust (`LWS_PASSPHRASE` is read when it is unset). Unset → the empty passphrase is tried; if that fails, the shielded and DUST balances are left out. Set but wrong → error. |
| `OWS_WALLET` | Default for `--wallet`. |
| `OWS_MIDNIGHT_SYNC_CACHE` | `0`/`false` → disable the disk snapshot cache (always re-sync). |

### The code path

- CLI: `commands/fund.rs::balance` detects a `midnight:*` chain, resolves the credential, builds
  the optional `MidnightCryptoProvider`, and calls `ows_midnight::print_fund_balance`.
- Display + concurrency: `ows-midnight/src/fund_balance.rs`.
- Streams (`wallet_sync/`): `unshielded.rs`, `shielded/` → `shielded/vk_hidden/` (the local
  Zswap replay), `dust/`.
- Cache + gating: `cache_io.rs` (which also reads `OWS_MIDNIGHT_SYNC_CACHE`), `shielded/cache.rs`,
  `shielded/vk_hidden/sync_cache.rs`, `dust/sync_cache.rs`, `tip_verify.rs`; the unshielded
  snapshot code lives in `unshielded.rs`.
- Fixed sync timeouts: `midnight_env.rs`.

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
`makerTx` (below).

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

Balancing brings every token back to zero in every segment, as the Midnight wallet SDK does: the
wallet adds inputs for whatever the transaction is short of, and an output to itself for any value no
output receives — its own change, a maker's surplus, or what a contract action left over. The ledger
rejects only a shortfall, so that value would otherwise be destroyed when the transaction is applied,
or, for NIGHT, fail the ledger's supply check.

An out-of-spec request (a proof-preimage input or a `ClaimRewards` mint claim) is rejected with a
**precise** error rather than a generic "unsupported". So is a dust registration the dapp put in the
transaction, unless it registers the wallet's own NIGHT to the wallet's own dust address and the
wallet adds no DUST of its own (`payFees: false`). A registration to any other dust address would
hand the wallet's DUST generation to someone else, and a deregistration would switch it off, so the
balancer and the signer both refuse them.

`ows sign tx` returns the fully sealed, proven Midnight transaction on `SignResult.transaction`
(`None` for other chains) — the seal-*without*-broadcast capability: the same bytes `send-tx`
broadcasts, surfaced through a command that never submits.

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
seeds and builds the `MidnightCryptoProvider`) or an **api-key token**, which goes through the same
policy check as on every other chain before the key is decrypted. That check sees the connector
request, the dapp's transaction, but not what the wallet adds while balancing it: its own inputs and
change, and the DUST fee. All bearer key material stays in `ows-signer`; `ows-midnight` holds none,
not even while sizing the fee, where the signer hands it mock-proven sections rather than the
key-bearing preimages (enforced by the `no_key_material_gate` workspace test).

### Node RPC

Submission talks to the Substrate node RPC, resolved **separately from the balance indexer**. Provide
it with `--rpc-url <url>`, else it resolves from `~/.ows/config.json` under
`rpc["midnight:<network>:node"]`. Only preview ships a default; for mainnet and preprod, set it
yourself, to a hosted endpoint from the same networks guide or to your own node. A plaintext
`http://` or `ws://` URL is accepted only for a loopback address, such as a local node; anything else
needs `https://` or `wss://`. Credentials in the URL never appear in error messages. Each node call
is bounded (connect 30s, request 60s), and a failed or timed-out submit names the transaction hash,
since the node may have accepted it: check whether it landed before retrying.

### Environment variables

| Variable | Effect |
|---|---|
| `OWS_PASSPHRASE` | Owner passphrase **or** api-key token; required to build the provider that signs/proves. |
| `OWS_WALLET` | Default for `--wallet`. |

### The code path

- CLI: `commands/send_transaction.rs` → `ows_lib::sign_and_send` (token) / `sign_encode_and_broadcast`
  (owner); Midnight routes through `decode_tx_input` → `prepare_signable_tx` (the plan/authorize seam).
- Balancing + seam: `ows-midnight/src/balance_tx.rs` (`plan_unsealed_proven_tx`, `authorize_proven_tx`),
  `balance_tx/fee_sizing.rs`, `dapp_connector/{mod,balance_unsealed}.rs`, `prover.rs`.
- Authorization (bearer instruments): `ows-signer/src/chains/midnight.rs`
  (`authorize_shielded`, `authorize_dust`, `sign_proven_intent`, `seal_signed_proven`).
- Submission: `ows-midnight/src/submit.rs`; node RPC config in `ows-core/src/config.rs`.

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
prefix. The result is the 32-byte x-only public key followed by the 64-byte signature, hex-encoded.

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
