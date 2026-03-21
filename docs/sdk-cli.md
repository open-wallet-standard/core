# CLI Reference

> Command-line interface for wallet management, export, and signing.

## Install

```bash
curl -fsSL https://openwallet.sh/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/open-wallet-standard/core.git
cd core/ows
cargo build --workspace --release
```

Wallet metadata is stored under `~/.ows/wallets/`. Mnemonics and private keys are stored in the OS keyring.

## Wallet Commands

### `ows wallet create`

Create a new wallet and store its mnemonic in the OS keyring.

```bash
ows wallet create --name "my-wallet"
```

| Flag | Description |
|---|---|
| `--name <NAME>` | Wallet name (required) |
| `--words <12|24>` | Mnemonic word count (default: 12) |
| `--show-mnemonic` | Print the generated mnemonic once for backup |

### `ows wallet import`

Import a wallet from a mnemonic or private key.

```bash
# Import from mnemonic (reads OWS_MNEMONIC or stdin)
echo "abandon abandon ..." | ows wallet import --name imported --mnemonic

# Import from private key (reads OWS_PRIVATE_KEY or stdin)
echo "4c0883a691..." | ows wallet import --name from-evm --private-key

# Import both curve keys from env vars
OWS_SECP256K1_KEY=4c0883a691... \
OWS_ED25519_KEY=9d61b19d... \
ows wallet import --name both
```

| Flag | Description |
|---|---|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private-key import (default: evm) |
| `--index <N>` | Account index for mnemonic import (default: 0) |

### `ows wallet export`

Export a wallet secret to stdout.

```bash
ows wallet export --wallet "my-wallet"
```

- Mnemonic wallets print the phrase.
- Private-key wallets print JSON with `secp256k1` and `ed25519`.

### `ows wallet list`

List wallet metadata stored in the vault.

```bash
ows wallet list
```

### `ows wallet rename`

Rename a wallet.

```bash
ows wallet rename --wallet old-name --new-name new-name
```

### `ows wallet delete`

Delete a wallet and its matching keyring entry.

```bash
ows wallet delete --wallet my-wallet --confirm
```

### `ows wallet info`

Show vault path and supported chains.

```bash
ows wallet info
```

## Signing Commands

### `ows sign message`

Sign a message with chain-specific formatting.

```bash
ows sign message --wallet my-wallet --chain evm --message "hello world"
```

| Flag | Description |
|---|---|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family or CAIP-2 chain ID |
| `--message <MSG>` | Message to sign |
| `--encoding <ENC>` | `utf8` (default) or `hex` |
| `--typed-data <JSON>` | EIP-712 typed data for EVM chains |
| `--index <N>` | Account index (default: 0) |
| `--json` | Print structured JSON output |

### `ows sign tx`

Sign a raw transaction.

```bash
ows sign tx --wallet my-wallet --chain evm --tx "02f8..."
```

| Flag | Description |
|---|---|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family or CAIP-2 chain ID |
| `--tx <HEX>` | Hex-encoded unsigned transaction bytes |
| `--index <N>` | Account index (default: 0) |
| `--json` | Print structured JSON output |

### `ows sign send-tx`

Sign and broadcast a transaction.

```bash
ows sign send-tx --wallet my-wallet --chain evm --tx "02f8..."
```

| Flag | Description |
|---|---|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family or CAIP-2 chain ID |
| `--tx <HEX>` | Hex-encoded unsigned transaction bytes |
| `--index <N>` | Account index (default: 0) |
| `--rpc-url <URL>` | Override the configured RPC endpoint |
| `--json` | Print structured JSON output |

## Mnemonic Commands

### `ows mnemonic generate`

Generate a mnemonic phrase.

```bash
ows mnemonic generate --words 24
```

### `ows mnemonic derive`

Derive an address from a mnemonic read from `OWS_MNEMONIC` or stdin.

```bash
echo "abandon abandon ..." | ows mnemonic derive --chain evm
```

## Vault Layout

```
~/.ows/
├── wallets/
│   └── <wallet-id>.json   # Wallet metadata
└── logs/
    └── audit.jsonl
```

The wallet file is metadata only. Secret material is stored in the OS keyring.
