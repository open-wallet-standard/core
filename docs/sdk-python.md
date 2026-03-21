# Python SDK

> Native bindings for Python via PyO3. No CLI, no server, no subprocess.

[![PyPI](https://img.shields.io/pypi/v/open-wallet-standard)](https://pypi.org/project/open-wallet-standard/)

## Install

```bash
pip install open-wallet-standard
```

Wallet metadata is stored under `~/.ows/wallets/`. Mnemonics and private keys are stored in the OS keyring.

## Quick Start

```python
from open_wallet_standard import (
    create_wallet,
    list_wallets,
    sign_message,
    export_wallet,
)

wallet = create_wallet("my-wallet")
wallets = list_wallets()
sig = sign_message("my-wallet", "evm", "hello")
phrase = export_wallet("my-wallet")

print(len(wallet["accounts"]))  # 7
print(len(wallets))
print(sig["signature"])
print(len(phrase.split()))
```

## Return Types

```python
# WalletInfo
{
    "id": "3198bc9c-...",
    "name": "my-wallet",
    "created_at": "2026-03-21T10:30:00Z",
    "accounts": [
        {
            "chain_id": "eip155:1",
            "address": "0xab16...",
            "derivation_path": "m/44'/60'/0'/0/0",
        }
    ],
}

# SignResult
{
    "signature": "bea6b4ee...",
    "recovery_id": 0,
}

# SendResult
{
    "tx_hash": "0xabc...",
}
```

## API

### Mnemonics

#### `generate_mnemonic(words=12)`

Generate a new 12- or 24-word mnemonic.

#### `derive_address(mnemonic, chain, index=None)`

Derive an address from a mnemonic without creating a wallet.

### Wallet Management

#### `create_wallet(name, words=None, vault_path_opt=None)`

Create a wallet, derive accounts for all supported chain families, store the secret in the OS keyring, and write wallet metadata to the vault.

#### `import_wallet_mnemonic(name, mnemonic, index=None, vault_path_opt=None)`

Import a mnemonic-backed wallet.

#### `import_wallet_private_key(name, private_key_hex, chain=None, vault_path_opt=None, secp256k1_key=None, ed25519_key=None)`

Import a private-key wallet. When only one curve key is provided, OWS generates the other curve's key so the wallet still has all 7 chain accounts.

#### `list_wallets(vault_path_opt=None)`

List wallet metadata from the vault.

#### `get_wallet(name_or_id, vault_path_opt=None)`

Load one wallet by name or ID.

#### `rename_wallet(name_or_id, new_name, vault_path_opt=None)`

Rename a wallet. The keyring entry stays stable because it is keyed by wallet ID.

#### `delete_wallet(name_or_id, vault_path_opt=None)`

Delete the metadata file and the matching keyring entry.

#### `export_wallet(name_or_id, vault_path_opt=None)`

Export the wallet secret.

- Mnemonic wallets return the phrase string.
- Private-key wallets return JSON with `secp256k1` and `ed25519` fields.

### Signing

#### `sign_message(wallet, chain, message, encoding=None, index=None, vault_path_opt=None)`

Sign a message with chain-specific formatting.

#### `sign_typed_data(wallet, chain, typed_data_json, index=None, vault_path_opt=None)`

Sign EIP-712 typed data for EVM chains.

#### `sign_transaction(wallet, chain, tx_hex, index=None, vault_path_opt=None)`

Sign a raw transaction.

#### `sign_and_send(wallet, chain, tx_hex, index=None, rpc_url=None, vault_path_opt=None)`

Sign and broadcast a transaction.

## Examples

### Import from mnemonic

```python
from open_wallet_standard import import_wallet_mnemonic

wallet = import_wallet_mnemonic(
    "imported",
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
)

print(len(wallet["accounts"]))  # 7
```

### Import explicit curve keys

```python
from open_wallet_standard import import_wallet_private_key

wallet = import_wallet_private_key(
    "both-keys",
    "",
    secp256k1_key="4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
    ed25519_key="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
)

print(len(wallet["accounts"]))  # 7
```

### Custom vault root

```python
from open_wallet_standard import create_wallet

wallet = create_wallet("isolated", vault_path_opt="/tmp/ows-test")
print(wallet["id"])
```

`vault_path_opt` points at the vault root, not the `wallets/` subdirectory. When omitted, OWS uses `~/.ows/`.
