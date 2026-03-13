# CLI Reference

> Command-line interface for managing wallets, signing, and key operations.

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

## Wallet Commands

### `ows wallet create`

Create a new wallet. Generates a BIP-39 mnemonic and derives addresses for all supported chains.

```bash
ows wallet create --name "my-wallet"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--passphrase <PASS>` | Encryption passphrase (prompted if omitted) |
| `--words <12\|24>` | Mnemonic word count (default: 12) |

Output:

```
Created wallet 3198bc9c-...
  eip155:1                              0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp  7Kz9...    m/44'/501'/0'/0'
  bip122:000000000019d6689c085ae165831e93   bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmoshub-4                     cosmos1... m/44'/118'/0'/0/0
  tron:mainnet                           TKLm...    m/44'/195'/0'/0/0
```

### `ows wallet import`

Import an existing wallet from a mnemonic or private key.

```bash
# Import from mnemonic (reads from OWS_MNEMONIC env or stdin)
echo "goose puzzle decorate ..." | ows wallet import --name "imported" --mnemonic

# Import from private key (reads from OWS_PRIVATE_KEY env or stdin)
echo "4c0883a691..." | ows wallet import --name "from-evm" --private-key

# Import an Ed25519 key (e.g. from Solana)
echo "9d61b19d..." | ows wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves (no stdin needed)
ows wallet import --name "both" \
  --secp256k1-key "4c0883a691..." \
  --ed25519-key "9d61b19d..."
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private key import (determines curve, default: evm) |
| `--index <N>` | Account index for HD derivation (mnemonic only, default: 0) |
| `--secp256k1-key <HEX>` | Explicit secp256k1 private key. When combined with `--ed25519-key`, `--private-key` is not required. |
| `--ed25519-key <HEX>` | Explicit Ed25519 private key. When combined with `--secp256k1-key`, `--private-key` is not required. |

Private key imports generate all 6 chain accounts: the provided key is used for its curve's chains, and a random key is generated for the other curve. Use `--secp256k1-key` and `--ed25519-key` together to supply both keys explicitly.

### `ows wallet export`

Export a wallet's secret to stdout. Requires an interactive terminal.

```bash
ows wallet export --wallet "my-wallet"
```

- Mnemonic wallets output the phrase.
- Private key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.

If the wallet is passphrase-protected, you will be prompted.

### `ows wallet list`

List all wallets in the vault.

```bash
ows wallet list
```

### `ows wallet info`

Show vault path and supported chains.

```bash
ows wallet info
```

## Signing Commands

### `ows sign message`

Sign a message with chain-specific formatting (e.g., EIP-191 for EVM, `\x19TRON Signed Message` for Tron).

```bash
ows sign message --wallet "my-wallet" --chain evm --message "hello world"
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family: `evm`, `solana`, `bitcoin`, `cosmos`, `tron` |
| `--message <MSG>` | Message to sign |
| `--passphrase <PASS>` | Decryption passphrase |
| `--encoding <ENC>` | Message encoding: `utf8` (default) or `hex` |

### `ows sign tx`

Sign a raw transaction (hex-encoded bytes).

```bash
ows sign tx --wallet "my-wallet" --chain evm --tx "02f8..."
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family |
| `--tx <HEX>` | Hex-encoded transaction bytes |
| `--passphrase <PASS>` | Decryption passphrase |

## Mnemonic Commands

### `ows mnemonic generate`

Generate a new BIP-39 mnemonic phrase.

```bash
ows mnemonic generate --words 24
```

### `ows mnemonic derive`

Derive an address from a mnemonic for a given chain. Reads the mnemonic from the `OWS_MNEMONIC` environment variable or stdin.

```bash
echo "word1 word2 ..." | ows mnemonic derive --chain evm
```

## System Commands

### `ows update`

Update the `ows` binary to the latest release. Also updates Node.js and Python bindings if they are installed.

```bash
ows update
ows update --force   # re-download even if already on latest
```

### `ows uninstall`

Remove `ows` from the system. Also uninstalls Node.js and Python bindings if present.

```bash
ows uninstall          # keep wallet data
ows uninstall --purge  # also remove ~/.ows (all wallet data)
```

## File Layout

```
~/.ows/
  bin/
    ows                  # CLI binary
  wallets/
    <uuid>/
      wallet.json        # Encrypted keystore (Keystore v3)
      meta.json          # Name, chain, creation time
```
