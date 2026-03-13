# OWS — Open Wallet Standard

Rust implementation of the [Open Wallet Standard](https://openwalletstandard.org) for secure, local-first crypto wallet management.

## Quick Install

```bash
curl -fsSL https://openwallet.sh/install.sh | bash
```

This installs the `ows` CLI binary, plus Node.js and Python bindings if those runtimes are available.

Or clone and build from source (requires [Rust](https://rustup.rs) 1.70+):

```bash
git clone https://github.com/open-wallet-standard/core.git
cd core/ows
cargo build --workspace --release
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `ows wallet create` | Create a new wallet (generates mnemonic, derives addresses for all chains) |
| `ows wallet list` | List all saved wallets in the vault |
| `ows wallet info` | Show vault path and supported chains |
| `ows sign message` | Sign a message using a vault wallet with chain-specific formatting |
| `ows sign tx` | Sign a raw transaction using a vault wallet |
| `ows mnemonic generate` | Generate a new BIP-39 mnemonic phrase |
| `ows mnemonic derive` | Derive an address from a mnemonic (via env or stdin) |
| `ows update` | Update ows and installed bindings to the latest version |
| `ows uninstall` | Remove ows and bindings from the system |

## Language Bindings

The bindings are **standalone** — they embed the Rust core via native FFI. No CLI or install script required.

| Language | Package | Install |
|----------|---------|---------|
| Node.js | [`@open-wallet-standard/node`](https://www.npmjs.com/package/@open-wallet-standard/node) | `npm install @open-wallet-standard/node` |
| Python | [`open-wallet-standard`](https://pypi.org/project/open-wallet-standard/) | `pip install open-wallet-standard` |

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/node";

const wallet = createWallet("my-wallet");
console.log(wallet.accounts); // addresses for EVM, Solana, Bitcoin, Cosmos, Tron

const sig = signMessage("my-wallet", "evm", "hello");
console.log(sig.signature);
```

## Crates

| Crate | Description |
|-------|-------------|
| `ows-core` | Types, CAIP-2/10 parsing, errors, config. Zero crypto dependencies. |
| `ows-signer` | ChainSigner trait, HD derivation, address derivation for EVM, Solana, Bitcoin, Cosmos, and Tron. |
| `ows-lib` | Library interface used by language bindings and the CLI. |
| `ows-cli` | The `ows` command-line tool. |

## Supported Chains

- **EVM** (Ethereum, Polygon, etc.) — secp256k1, EIP-55 addresses, EIP-191 message signing
- **Solana** — Ed25519, base58 addresses
- **Bitcoin** — secp256k1, BIP-84 native segwit (bech32)
- **Cosmos** — secp256k1, bech32 addresses (configurable HRP)
- **Tron** — secp256k1, base58check addresses

## License

See repository root for license information.
