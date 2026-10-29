# e2e — DApp Connector sibling methods (live, preview)

Validates the four connector methods end-to-end through the real pipeline
(`decode_tx_input → prepare_signable_tx → plan_connector_tx → ConnectorPlan::authorize
→ sign → prove → seal`). All four flow through the connector `--tx`, which carries the
**connector request JSON verbatim** (see `decode_tx_input`).

These require a local prover (circuit keys, fetched on first use into
`~/.ows/chains/midnight/proving-keys`) + a funded preview wallet + indexer — they can't
run in CI. Run them by hand on preview.

## Prerequisites

- Built release CLI: `cargo build --manifest-path ows/Cargo.toml --release`
- A funded preview wallet (the notes use `length-wallet`, unlocked by an empty passphrase).
- **Sealing vs broadcasting:**
  - `ows sign tx --json` plans → authorizes → proves → **seals** and returns the sealed hex on
    `SignResult.transaction`. It does **not** broadcast — use it to inspect/hand off the hex.
  - `ows sign send-tx --json` does the same **and broadcasts**, returning `{ "tx_hash": "0x…" }`.
- Recipient addresses: use your own wallet's addresses (self-transfer) so value doesn't leave, or a
  second wallet you control. The `Addresses:` block of `ows fund balance` prints them:
  `mn_addr_preview1…` = unshielded, `mn_shield-addr_preview1…` = shielded.

```sh
OWS=ows/target/release/ows
CHAIN=midnight:preview
WALLET=length-wallet
export OWS_PASSPHRASE=          # empty unlocks length-wallet
```

## 1. makeTransfer — build + balance + prove + seal (+ broadcast)

The wallet constructs the outputs (a deficit), then balances with its own inputs. Fees are paid in
**dust**, not in the transferred token.

```sh
# Seal without broadcasting (inspect the hex):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "method": "makeTransfer",
  "desiredOutputs": [
    { "kind": "unshielded", "type": "night", "value": "1000000", "recipient": "<mn_addr_preview1…self>" }
  ],
  "options": { "payFees": true }
}'
# → { "recovery_id", "signature", "transaction": "0x…sealed hex" }

# Broadcast (returns the txhash):
$OWS sign send-tx --chain $CHAIN --wallet $WALLET --json --tx '{ …same request… }'
# → { "chain": "midnight:preview", "tx_hash": "0x…" }
```

Verify on-chain (and check the recipient credit equals the requested value):

```sh
curl -s https://indexer.preview.midnight.network/api/v4/graphql \
  -H 'content-type: application/json' \
  -d '{"query":"{ transactions(offset:{hash:\"0x<HASH>\"}){ block{height} unshieldedCreatedOutputs{ owner value tokenType } } }"}'
```

Also try a shielded output (`"kind":"shielded"`, a `mn_shield-addr_preview1…` recipient). Note the wallet
must hold the shielded token being sent — native **shielded** NIGHT is often 0; use a custom shielded
token the wallet holds (`"type":"<0x…32-byte-hex>"`).

## 2. makeIntent — imbalanced maker offer (export, do NOT submit)

Maker contributes real unshielded inputs and declares wanted outputs; the result is deliberately
imbalanced, so seal it with `sign tx` (no broadcast) and hand the hex to the taker (step 3).

```sh
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "method": "makeIntent",
  "desiredInputs":  [ { "kind": "unshielded", "type": "<other-token-hex>", "value": "10" } ],
  "desiredOutputs": [ { "kind": "unshielded", "type": "night", "value": "500000", "recipient": "<mn_addr_preview1…self>" } ],
  "options": { "intentId": 1, "payFees": false }
}'
```

Expect: a proven, imbalanced maker offer. (`payFees: true` is rejected here — the taker funds the
DUST fee when it completes the swap.) `sign tx` seals it as a **fully-sealed**
(`proof,pedersen-schnorr`) offer — which a taker completes by MERGING in its complement (step 3).

## 3. balanceSealedTransaction — taker completes the maker offer

Feed a sealed maker offer as `makerTx`; the taker's wallet builds its complementary half, funds it,
seals it and merges the two.

```sh
# A FULLY-SEALED maker offer (proof,pedersen-schnorr — e.g. the step-2 output) is completed by MERGING:
$OWS sign tx --chain $CHAIN --wallet <taker-wallet> --json --tx '{
  "method": "balanceSealedTransaction",
  "makerTx": "<fully-sealed-maker-hex>",
  "options": { "payFees": true }
}'
#   → { … "transaction": "0x…merged+sealed hex" }
#     the taker builds the per-token complement of the maker's imbalance, funds the merged tx's dust fee,
#     seals its half, and Transaction::merge's the two into a balanced, submittable whole.
```

> **Note:** `sign tx`'s makeIntent output is *fully sealed*, so the step-2→step-3 chain completes by
> MERGING (above). A proven, unsealed (`proof,embedded-fr`) maker is refused: `balanceSealedTransaction`
> takes a sealed offer, and a proven transaction is `balanceUnsealedTransaction`'s input (§4). A taker
> with no dust pays the fee by registering an unregistered NIGHT coin that has generated enough DUST, as
> `makeTransfer` does, so a freshly-funded wallet can be the taker once its NIGHT has aged.

> **Segment placement.** The maker offer must keep all its value in the guaranteed section (segment 0),
> as MIP-0006's swap offers do. A maker with shielded coins, unshielded inputs or outputs, or an
> imbalance in a fallible segment is refused (`refusing a maker offer with … in fallible segment N`):
> the ledger applies a fallible segment on its own, so it could fail while the taker's payment in
> segment 0 stands. `makeIntent` keeps every leg in segment 0.

## 4. balanceUnsealedTransaction — regression (unchanged)

The dapp hands the wallet an already-**proven** (`proof,embedded-fr`) unsealed tx; the wallet balances it
against its own inputs, then signs and seals.

```sh
# 4a. proof,embedded-fr → balanced + sealed (the spec-conformant input):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "tx": "<proof,embedded-fr hex, e.g. e2e/shielded-movement-cap/tx-proven.hex>",
  "options": { "payFees": true }
}'
#   → { … "transaction": "0x…" }

# 4b. proof-preimage → REJECTED (the dapp must prove its own part first):
$OWS sign tx --chain $CHAIN --wallet $WALLET --json --tx '{
  "tx": "<proof-preimage hex, e.g. e2e/shielded-movement-cap/tx.hex>",
  "options": { "payFees": true }
}'
#   → error: … expects a proven (proof,embedded-fr) transaction … received a proof-preimage transaction
```

> **Supported shapes.** In-place balancing handles a transaction that carries **no unshielded inputs of
> its own**: the wallet supplies *and signs* the balancing inputs and cannot sign an input belonging to
> anyone else, so a proven tx that already holds foreign unshielded inputs is rejected (`transaction
> carries dapp-provided unshielded inputs, which is unsupported`).

## Coverage note

Supported: `makeIntent` **shielded inputs** — whole-coin spend with per-token change to the maker,
live-validated via the makeIntent → `balanceSealed` merge round-trip — and `balanceSealed`
**MIP-0005** (`swapoffer` bech32, decoded to the sealed maker and completed by merging) and
**MIP-0006** (an indexer's offer payload, as a JSON string in `makerTx`, checked against its offer)
inputs. Both are unit-tested against a real preprod sealed maker, and both landed on preview: a
makeIntent offer completed from its `swapoffer` string, and another from a MIP-0006 payload built
around it. An offer served by a MIP-0006 indexer has not been tried yet.

Still out of spec (reject with a precise error): a `proof-preimage` maker, a dust registration to
anyone but the wallet itself, and a `ClaimRewards` mint.
