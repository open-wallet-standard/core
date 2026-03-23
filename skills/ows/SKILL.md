---
name: ows
description: Secure, local-first multi-chain wallet management — create wallets, derive addresses, sign messages and transactions across EVM, Solana, Sui, Bitcoin, Cosmos, Tron, and TON via CLI, Node.js, or Python.
version: 0.4.2
metadata:
  openclaw:
    requires:
      anyBins:
        - ows
        - node
        - python3
    emoji: "\U0001F511"
    homepage: https://openwallet.sh
    os:
      - darwin
      - linux
    install:
      - kind: node
        package: "@open-wallet-standard/core"
        bins: [ows]
        label: Install OWS Node.js SDK + CLI
---

# OWS — Open Wallet Standard

Secure, offline-first multi-chain wallet management. Private keys are encrypted at rest (AES-256-GCM, scrypt KDF) and decrypted only inside an isolated signing process — the caller never sees the raw key.

Available as **CLI**, **Node.js SDK** (`@open-wallet-standard/core`), and **Python SDK** (`open-wallet-standard`).

## When to use

Use this skill when the user asks to:

- Create, import, list, delete, or manage crypto wallets
- Derive blockchain addresses from a mnemonic
- Sign messages or transactions for EVM, Solana, Sui, Bitcoin, Cosmos, Tron, or TON
- Broadcast signed transactions to a chain
- Generate BIP-39 mnemonic phrases
- Work with `@open-wallet-standard/core` or `open-wallet-standard` in code

## Supported Chains

| Chain | Parameter | Curve | Address Format |
|-------|-----------|-------|----------------|
| EVM (Ethereum, Polygon, Base, etc.) | `evm` | secp256k1 | EIP-55 checksummed |
| Solana | `solana` | Ed25519 | base58 |
| Bitcoin | `bitcoin` | secp256k1 | BIP-84 bech32 |
| Cosmos | `cosmos` | secp256k1 | bech32 |
| Tron | `tron` | secp256k1 | base58check |
| TON | `ton` | Ed25519 | raw/bounceable |
| Sui | `sui` | Ed25519 | 0x + BLAKE2b-256 hex |

## Installation

```bash
# CLI (one-liner)
curl -fsSL https://openwallet.sh/install.sh | bash

# Node.js SDK (global install also provides the ows CLI)
npm install @open-wallet-standard/core

# Python SDK
pip install open-wallet-standard
```

---

## CLI

### Wallet Management

```bash
# Create (--show-mnemonic to display the phrase for backup)
ows wallet create --name "my-wallet"
ows wallet create --name "my-wallet" --words 24 --show-mnemonic

# Import from mnemonic (via stdin or OWS_MNEMONIC env)
echo "goose puzzle decorate ..." | ows wallet import --name "imported" --mnemonic

# Import from private key (via stdin or OWS_PRIVATE_KEY env)
echo "4c0883a691..." | ows wallet import --name "from-evm" --private-key
echo "9d61b19d..." | ows wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves
ows wallet import --name "both" \
  --secp256k1-key "4c0883a691..." \
  --ed25519-key "9d61b19d..."

# List / info / export / delete / rename
ows wallet list
ows wallet info
ows wallet export --wallet "my-wallet"
ows wallet delete --wallet "my-wallet" --confirm
ows wallet rename --wallet "my-wallet" --new-name "treasury"
```

### Signing

The `--wallet` flag can also be set via `OWS_WALLET` env var. Use `--json` for structured output, `--index N` to select an HD account index.

```bash
# Sign a message
ows sign message --wallet "my-wallet" --chain evm --message "hello world"
ows sign message --wallet "my-wallet" --chain solana --message "hello" --json

# Sign a message with EIP-712 typed data (EVM only)
ows sign message --wallet "my-wallet" --chain evm --message "" --typed-data '{"types":...}'

# Sign a raw transaction
ows sign tx --wallet "my-wallet" --chain evm --tx "02f8..."

# Sign and broadcast
ows sign send-tx --wallet "my-wallet" --chain evm --tx "02f8..." --rpc-url "https://..."
```

### Mnemonic Utilities

```bash
ows mnemonic generate --words 12
OWS_MNEMONIC="word1 word2 ..." ows mnemonic derive --chain evm
```

### System

```bash
ows update            # Update to latest version
ows update --force    # Force re-download
ows uninstall         # Remove CLI (keep wallet data)
ows uninstall --purge # Remove CLI + all wallet data
ows config show       # Show config and RPC endpoints
```

---

## Node.js SDK

`npm install @open-wallet-standard/core` — native NAPI bindings, Rust core runs in-process.

Quick start:

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("my-wallet");
const sig = signMessage("my-wallet", "evm", "hello world");
```

Full API reference, types, and examples: see `{baseDir}/references/node.md`

---

## Python SDK

`pip install open-wallet-standard` — native PyO3 bindings, Rust core runs in-process.

Quick start:

```python
from open_wallet_standard import create_wallet, sign_message

wallet = create_wallet("my-wallet")
sig = sign_message("my-wallet", "evm", "hello world")
```

Full API reference, return types, and examples: see `{baseDir}/references/python.md`

---

## Vault Layout

```
~/.ows/
  bin/
    ows                    # CLI binary
  wallets/
    <uuid>/
      wallet.json          # Encrypted keystore (AES-256-GCM, scrypt KDF)
      meta.json            # Name, chains, created_at
```

## Security Model

- Keys encrypted at rest with AES-256-GCM (scrypt N=2^15, r=8, p=1)
- Signing in isolated process — keys decrypted, used, wiped from memory
- Caller never sees raw private key during signing
- Optional passphrase adds second encryption layer
- Universal wallets: single mnemonic derives addresses for all supported chains via BIP-44 HD paths
