# open-wallet-standard

Secure signing and wallet management for every chain. One vault, one interface — keys never leave your machine.

[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

{{> why-ows}}

## Install

```bash
pip install open-wallet-standard
```

The package is **fully self-contained** — it embeds the Rust core via native FFI. No additional dependencies required.

## Quick Start

```python
from ows import create_wallet, sign_message

wallet = create_wallet("agent-treasury")
# => accounts for EVM, Solana, Sui, BTC, Cosmos, Tron, TON

sig = sign_message("agent-treasury", "evm", "hello")
print(sig["signature"])
```

## API Reference

| Function | Description |
|----------|-------------|
| `create_wallet(name)` | Create a new wallet with addresses for all chains |
| `import_wallet_mnemonic(name, mnemonic)` | Import a wallet from a BIP-39 mnemonic |
| `import_wallet_private_key(name, chain, private_key)` | Import a wallet from a private key |
| `list_wallets()` | List all wallets in the vault |
| `get_wallet(name)` | Get details of a specific wallet |
| `delete_wallet(name)` | Delete a wallet |
| `export_wallet(name)` | Export a wallet's mnemonic |
| `rename_wallet(old_name, new_name)` | Rename a wallet |
| `sign_message(wallet, chain, message)` | Sign a message with chain-specific formatting |
| `sign_transaction(wallet, chain, tx)` | Sign a raw transaction |
| `sign_and_send(wallet, chain, tx)` | Sign and broadcast a transaction |
| `generate_mnemonic()` | Generate a BIP-39 mnemonic phrase |
| `derive_address(mnemonic, chain)` | Derive an address from a mnemonic |

{{> supported-chains}}

{{> architecture}}

## Documentation

The full spec and docs are available at [openwallet.sh](https://openwallet.sh) and in the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT