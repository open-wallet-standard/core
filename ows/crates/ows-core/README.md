<!-- Generated from readme/templates/ows.md + readme/partials/ — edit those, then run readme/generate.sh -->

# OWS — Open Wallet Standard

Rust implementation of the [Open Wallet Standard](https://openwallet.sh) for secure, local-first crypto wallet management.

## Quick Install

```bash
curl -fsSL https://docs.openwallet.sh/install.sh | bash
```

This installs the `ows` CLI binary, plus Node.js and Python bindings if those runtimes are available.

Or clone and build from source (requires [Rust](https://rustup.rs) 1.70+):

```bash
git clone https://github.com/open-wallet-standard/core.git
cd core/ows
cargo build --workspace --release
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `ows wallet create` | Create a new wallet with addresses for all chains |
| `ows wallet list` | List all wallets in the vault |
| `ows wallet info` | Show vault path and supported chains |
| `ows sign message` | Sign a message with chain-specific formatting |
| `ows sign tx` | Sign a raw transaction |
| `ows pay request` | Make a paid request to an x402-enabled API endpoint |
| `ows pay discover` | Discover x402-enabled services |
| `ows fund deposit` | Create a MoonPay deposit to fund a wallet with USDC |
| `ows fund balance` | Check token balances for a wallet |
| `ows mnemonic generate` | Generate a BIP-39 mnemonic phrase |
| `ows mnemonic derive` | Derive an address from a mnemonic |
| `ows policy create` | Register a policy from a JSON file |
| `ows policy list` | List all registered policies |
| `ows key create` | Create an API key for agent access |
| `ows key list` | List all API keys |
| `ows key revoke` | Revoke an API key |
| `ows update` | Update ows and bindings |
| `ows uninstall` | Remove ows from the system |

## Language Bindings

The bindings are **standalone** — they embed the Rust core via native FFI. No CLI or install script required.

| Language | Package | Install |
|----------|---------|---------|
| Node.js | [`@open-wallet-standard/core`](https://www.npmjs.com/package/@open-wallet-standard/core) | `npm install @open-wallet-standard/core` |
| Python | [`open-wallet-standard`](https://pypi.org/project/open-wallet-standard/) | `pip install open-wallet-standard` |

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("my-wallet");
console.log(wallet.accounts); // addresses for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, Sui, and XRPL

const sig = signMessage("my-wallet", "evm", "hello");
console.log(sig.signature);
```

## Crates

| Crate | Description |
|-------|-------------|
| `ows-core` | Types, CAIP-2/10 parsing, errors, config. Zero crypto dependencies. |
| `ows-signer` | ChainSigner trait, HD derivation, address derivation for EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, and Filecoin. |
| `ows-lib` | Library interface used by language bindings and the CLI. |
| `ows-pay` | x402 payment flows, service discovery, and funding helpers. |
| `ows-cli` | The `ows` command-line tool. |

## Supported Chains

- **EVM** (Ethereum, Polygon, etc.) — secp256k1, EIP-55 addresses, EIP-191 message signing
- **Solana** — Ed25519, base58 addresses
- **Sui** — Ed25519, BLAKE2b-256 hex addresses
- **Bitcoin** — secp256k1, BIP-84 native segwit (bech32)
- **Cosmos** — secp256k1, bech32 addresses (configurable HRP)
- **Tron** — secp256k1, base58check addresses
- **TON** — Ed25519, raw/bounceable addresses
- **Spark** (Bitcoin L2) — secp256k1, spark: prefixed addresses
- **XRPL** — secp256k1, Base58Check r-addresses
- **Filecoin** — secp256k1, f1 base32 addresses

## License

See repository root for license information.
