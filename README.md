# LWS — Local Wallet Standard

Secure signing and wallet management for every chain. One vault, one interface — keys never leave your machine.

[![CI](https://github.com/dawnlabsai/lws/actions/workflows/ci.yml/badge.svg)](https://github.com/dawnlabsai/lws/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@local-wallet-standard/node)](https://www.npmjs.com/package/@local-wallet-standard/node)
[![PyPI](https://img.shields.io/pypi/v/local-wallet-standard)](https://pypi.org/project/local-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why LWS

- **Zero key exposure.** Private keys are encrypted at rest, decrypted only inside an isolated signing process. Agents and LLMs never see raw key material.
- **Every chain, one interface.** EVM, Solana, Bitcoin, Cosmos, Tron, TON — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates every operation — spending limits, allowlists, chain restrictions — before any key is touched.
- **Built for agents.** MCP server, native SDK, and CLI. A wallet created by one tool works in every other.

## Install

```bash
# Everything (CLI + Node + Python bindings)
curl -fsSL https://openwallet.sh/install.sh | bash
```

Or install only what you need:

```bash
npm install @local-wallet-standard/node    # Node.js
pip install local-wallet-standard           # Python
cd lws && cargo build --workspace --release # From source
```

The language bindings are **fully self-contained** — they embed the Rust core via native FFI. No CLI required.

## Quick Start

```bash
# Create a wallet (derives addresses for all supported chains)
lws wallet create --name "agent-treasury"

# Sign a message
lws sign message --wallet agent-treasury --chain evm --message "hello"

# Sign a transaction
lws sign tx --wallet agent-treasury --chain evm --tx-hex "deadbeef..."
```

```javascript
import { createWallet, signMessage } from "@local-wallet-standard/node";

const wallet = createWallet("agent-treasury");
// => accounts for EVM, Solana, BTC, Cosmos, Tron, TON

const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);
```

```python
from local_wallet_standard import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, BTC, Cosmos, Tron, TON

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

## Architecture

```
Agent / CLI / App
       │
       │  LWS Interface (MCP / SDK / CLI)
       ▼
┌─────────────────────┐
│    Access Layer      │     1. Agent calls lws.sign()
│  ┌────────────────┐  │     2. Policy engine evaluates
│  │ Policy Engine   │  │     3. Enclave decrypts key
│  │ (pre-signing)   │  │     4. Transaction signed
│  └───────┬────────┘  │     5. Key wiped from memory
│  ┌───────▼────────┐  │     6. Signature returned
│  │ Signing Enclave │  │
│  │ (isolated proc) │  │     The agent NEVER sees
│  └───────┬────────┘  │     the private key.
│  ┌───────▼────────┐  │
│  │  Wallet Vault   │  │
│  │ ~/.lws/wallets/ │  │
│  └────────────────┘  │
└─────────────────────┘
```

## Supported Chains

| Chain | Curve | Address Format | Derivation Path |
|-------|-------|----------------|-----------------|
| EVM (Ethereum, Polygon, etc.) | secp256k1 | EIP-55 checksummed | `m/44'/60'/0'/0/0` |
| Solana | Ed25519 | base58 | `m/44'/501'/0'/0'` |
| Bitcoin | secp256k1 | BIP-84 bech32 | `m/84'/0'/0'/0/0` |
| Cosmos | secp256k1 | bech32 | `m/44'/118'/0'/0/0` |
| Tron | secp256k1 | base58check | `m/44'/195'/0'/0/0` |
| TON | Ed25519 | raw/bounceable | `m/44'/607'/0'` |

## CLI Reference

| Command | Description |
|---------|-------------|
| `lws wallet create` | Create a new wallet with addresses for all chains |
| `lws wallet list` | List all wallets in the vault |
| `lws wallet info` | Show vault path and supported chains |
| `lws sign message` | Sign a message with chain-specific formatting |
| `lws sign tx` | Sign a raw transaction |
| `lws mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `lws mnemonic derive` | Derive an address from a mnemonic |
| `lws update` | Update lws and bindings |
| `lws uninstall` | Remove lws from the system |

## Specification

The full spec lives in [`docs/`](docs/) and at [openwallet.sh](https://openwallet.sh):

1. [Storage Format](docs/01-storage-format.md) — Vault layout, Keystore v3, filesystem permissions
2. [Chain-Agnostic Addressing](docs/02-chain-agnostic-addressing.md) — CAIP-2/CAIP-10 standards
3. [Signing Interface](docs/03-signing-interface.md) — sign, signAndSend, signMessage operations
4. [Policy Engine](docs/04-policy-engine.md) — Pre-signing transaction policies
5. [Key Isolation](docs/05-key-isolation.md) — HD derivation paths and key separation
6. [Agent Access Layer](docs/06-agent-access-layer.md) — MCP server, native language bindings
7. [Multi-Chain Support](docs/07-multi-chain-support.md) — Chain plugin interface
8. [Wallet Lifecycle](docs/08-wallet-lifecycle.md) — Creation, recovery, deletion

## License

MIT
