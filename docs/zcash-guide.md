# Zcash Integration Guide

Zcash is the first privacy-preserving chain in OWS. It supports shielded transactions via the PCZT (Partially Created Zcash Transaction) format, giving agents and wallets a way to hold and spend ZEC without exposing transaction metadata.

## How Zcash differs from other OWS chains

Every other chain in OWS follows the same pattern: derive a key via BIP-44, hash and sign a transaction, broadcast via JSON-RPC. Zcash breaks this pattern in two ways:

1. **Key derivation uses ZIP-32, not BIP-44.** Zcash unified addresses contain Orchard and Sapling receivers, which require the raw BIP-39 seed passed through the ZIP-32 derivation scheme — not a BIP-32 derived private key.

2. **Signing operates on PCZTs, not raw transactions.** Zcash shielded transactions require zero-knowledge proofs and per-pool spend authorization signatures (RedPallas for Orchard, Jubjub for Sapling). OWS handles only the signing step. The ZK proof generation happens externally.

## Wallet creation

```bash
ows wallet create --name my-wallet
```

Zcash appears alongside all other chains. The derived address is a unified address (`u1...`) with Orchard and Sapling receivers — shielded by default.

```
eip155:1    → 0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb
solana:...  → 7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q
zcash:mainnet → u1qxnwj8h...
```

Under the hood, OWS detects that the Zcash signer requires the raw seed (`needs_raw_seed() → true`) and passes the full 64-byte BIP-39 seed through ZIP-32 derivation instead of BIP-44:

```
BIP-39 Mnemonic
    │
    ▼
Raw Seed (64 bytes)
    │
    ├── BIP-44 path  → EVM, Solana, Bitcoin, ...
    │
    └── ZIP-32       → Unified Spending Key
                          │
                          ├── Orchard receiver
                          ├── Sapling receiver
                          └── Unified Address (u1...)
```

## Address derivation

To derive a Zcash address from an existing mnemonic:

```bash
echo "your twelve word mnemonic ..." | ows derive --chain zcash
```

This returns a unified address. To derive all chains at once:

```bash
echo "your twelve word mnemonic ..." | ows derive
```

## Signing a PCZT

### The PCZT pipeline

Zcash transactions are built collaboratively using the PCZT format. The roles are:

```
Creator      →  Builds the transaction structure (inputs, outputs, amounts)
    │
Prover       →  Generates zero-knowledge proofs (Sapling, Orchard)
    │
Signer (OWS) →  Applies spend authorization signatures
    │
Finalizer    →  Extracts the signed transaction
    │
Broadcaster  →  Sends to the network via lightwalletd
```

OWS fills the **Signer** role. It receives a PCZT that already has ZK proofs applied, decrypts the spending key from the vault, signs the relevant inputs, and returns the signed PCZT.

### CLI usage

```bash
# Sign a PCZT (hex-encoded)
ows sign tx --chain zcash --wallet my-wallet --tx <pczt_hex>
```

The `<pczt_hex>` must be a serialized PCZT that has already been through the Creator and Prover stages. Tools that produce PCZTs include:

- **zipher-cli** (`zipher create-pczt`)
- **Zodl** (the Zcash reference wallet, via `zcash_client_backend`)
- Any tool using `zcash_client_backend::data_api::wallet::create_pczt_from_proposal`

The output is the signed PCZT in hex. The caller is responsible for finalization and broadcast.

### Security: trusting the PCZT source

OWS signs whatever PCZT is passed to it — the same trust model as every other chain. When you call `ows sign tx --chain evm`, OWS signs the unsigned EVM transaction without inspecting whether the recipient or amount is what you intended. The caller (your agent, your CLI, your wallet) is responsible for constructing a safe transaction.

For Zcash, this means: if a malicious PCZT is constructed to send your funds to an attacker's address, OWS will sign it. The PCZT format does carry metadata (amounts, recipients, memos) that a higher-level application could inspect before requesting a signature, but OWS itself operates at the signing primitive level — it does not enforce spending policies at the PCZT layer.

This is consistent with the OWS security model: the vault holds keys, the signer signs, and the policy engine (if configured) enforces spending limits. Transaction construction and validation are the caller's responsibility across all chains.

### Sign and broadcast

For end-to-end sending:

```bash
ows sign send-tx --chain zcash --wallet my-wallet --tx <pczt_hex>
```

This signs the PCZT, extracts the finalized transaction, and broadcasts it to lightwalletd via gRPC. The default endpoint is `zec.rocks:443` for mainnet.

Returns the transaction ID (txid) on success.

## What OWS signs

When `sign tx --chain zcash` is called, OWS:

1. Decrypts the BIP-39 mnemonic from the vault
2. Derives the Unified Spending Key via ZIP-32
3. Extracts per-pool signing keys:
   - **Orchard:** `SpendAuthorizingKey` (RedPallas)
   - **Sapling:** `ask` (Jubjub)
   - **Transparent:** secp256k1 secret key
4. Iterates over PCZT inputs and signs those matching the derived keys
5. Skips dummy/padding actions (standard Orchard behavior)
6. Returns the signed PCZT

The spending key is zeroized after use.

## Configuration

### Default RPC endpoints

| Network | Endpoint |
|---------|----------|
| `zcash:mainnet` | `https://zec.rocks:443` |
| `zcash:testnet` | `https://testnet.zec.rocks:443` |

Override via `~/.ows/config.toml`:

```toml
[rpc]
"zcash:mainnet" = "https://your-lightwalletd:443"
```

Or pass `--rpc-url` on the CLI.

### Feature flag

Zcash shielded support requires the `zcash-shielded` feature flag, which is enabled by default in the CLI. The feature adds dependencies on `zcash_keys`, `pczt`, `orchard`, and `sapling-crypto` for ZIP-32 derivation and PCZT signing.

Without `zcash-shielded`, Zcash falls back to transparent-only support (t-addresses, secp256k1 signing).

## Dependencies

| Crate | Purpose |
|-------|---------|
| `zcash_keys` 0.12 | ZIP-32 key derivation, unified address encoding |
| `zcash_protocol` 0.7 | Network parameters (mainnet/testnet) |
| `zip32` 0.2 | Account ID types |
| `pczt` 0.5 | PCZT parsing, Signer role |
| `orchard` 0.11 | Orchard spend authorization key types |
| `sapling-crypto` 0.5 | Sapling spend auth key (`ask`) |
| `zcash_transparent` 0.6 | Transparent key derivation |
| `zcash_primitives` 0.26 | Transaction serialization (for broadcast) |

All crates are from the official [librustzcash](https://github.com/zcash/librustzcash) ecosystem, originally built by Electric Coin Company and now maintained by [ZODL](https://zodl.com) (Zcash Open Development Lab).

## End-to-end example

A complete shielded send using OWS and zipher-cli:

```bash
# 1. Create an OWS wallet
ows wallet create --name agent-wallet

# 2. Fund the Zcash address (send ZEC to the u1... address)

# 3. Build a PCZT with zipher-cli (Creator + Prover)
PCZT=$(zipher create-pczt \
  --to u1recipient... \
  --amount 0.01 \
  --data-dir ~/.zipher)

# 4. Sign with OWS (Signer)
ows sign send-tx --chain zcash --wallet agent-wallet --tx $PCZT

# 5. Transaction is broadcast and visible on a block explorer
```

## References

- [ZIP-32: Shielded Hierarchical Deterministic Wallets](https://zips.z.cash/zip-0032)
- [ZIP-316: Unified Addresses](https://zips.z.cash/zip-0316)
- [ZIP-244: Transaction Identifier and Commitment](https://zips.z.cash/zip-0244)
- [PCZT specification](https://github.com/zcash/zips/pull/766)
- [OWS Signing Interface](02-signing-interface.md)
- [OWS Supported Chains](07-supported-chains.md)
