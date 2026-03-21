# 04 - Agent Access Layer

> How applications, agents, and the CLI access OWS wallets through the shared Rust core.

## Implementation Status

| Feature | Status | Notes |
|---|---|---|
| `generate_mnemonic(words?)` | Done | 12 or 24 words |
| `derive_address(mnemonic, chain, index?)` | Done | |
| `create_wallet(name, words?, vault_path?)` | Done | Stores secrets in the OS keyring |
| `import_wallet_mnemonic(...)` | Done | |
| `import_wallet_private_key(...)` | Done | |
| `list_wallets(vault_path?)` | Done | Reads wallet metadata files |
| `get_wallet(name_or_id, vault_path?)` | Done | |
| `delete_wallet(name_or_id, vault_path?)` | Done | Removes file + keyring entry |
| `export_wallet(name_or_id, vault_path?)` | Done | Reads secret from keyring |
| `rename_wallet(name_or_id, new_name, vault_path?)` | Done | Metadata only |
| `sign_transaction(...)` | Done | Uses keyring-backed secret resolution |
| `sign_message(...)` | Done | |
| `sign_typed_data(...)` | Done | EVM only |
| `sign_and_send(...)` | Done | |
| Node.js NAPI bindings | Done | `bindings/node/src/lib.rs` |
| Python PyO3 bindings | Done | `bindings/python/src/lib.rs` |

## Design Decision

**OWS exposes one Rust implementation through native bindings and the CLI.**

There is no required background daemon and no HTTP API in the current model. All callers use the same library surface:

1. Read wallet metadata from the vault.
2. Resolve `secret_ref` from the wallet file.
3. Load the wallet secret from the OS keyring.
4. Perform export, signing, or broadcast.

If the OS keyring is unavailable, secret-dependent operations fail explicitly. OWS does not silently fall back to embedded file secrets for new wallets.

## Node.js Example

```typescript
import {
  createWallet,
  listWallets,
  signMessage,
  signAndSend,
} from "@open-wallet-standard/core";

const wallet = createWallet("agent-treasury");
const wallets = listWallets();

const sig = signMessage("agent-treasury", "evm", "hello");
const result = signAndSend("agent-treasury", "evm", "<tx-hex>");
```

## Python Example

```python
from open_wallet_standard import (
    create_wallet,
    list_wallets,
    sign_message,
    sign_and_send,
)

wallet = create_wallet("agent-treasury")
wallets = list_wallets()

sig = sign_message("agent-treasury", "evm", "hello")
result = sign_and_send("agent-treasury", "evm", "<tx-hex>")
```

## Available Operations

Node uses camelCase names. Python uses snake_case names. Both bindings expose the same operations:

| Operation | Description |
|---|---|
| `generate_mnemonic(words?)` | Generate a BIP-39 mnemonic |
| `derive_address(mnemonic, chain, index?)` | Derive an address without creating a wallet |
| `create_wallet(name, words?, vault_path?)` | Create a wallet and store its secret in the OS keyring |
| `import_wallet_mnemonic(name, mnemonic, index?, vault_path?)` | Import a mnemonic-backed wallet |
| `import_wallet_private_key(name, private_key_hex, chain?, vault_path?, secp256k1_key?, ed25519_key?)` | Import a private-key wallet |
| `list_wallets(vault_path?)` | List wallet metadata |
| `get_wallet(name_or_id, vault_path?)` | Load one wallet's metadata |
| `delete_wallet(name_or_id, vault_path?)` | Delete a wallet |
| `export_wallet(name_or_id, vault_path?)` | Export the wallet secret |
| `rename_wallet(name_or_id, new_name, vault_path?)` | Rename a wallet |
| `sign_transaction(wallet, chain, tx_hex, index?, vault_path?)` | Sign a transaction |
| `sign_message(wallet, chain, message, encoding?, index?, vault_path?)` | Sign a message |
| `sign_typed_data(wallet, chain, typed_data_json, index?, vault_path?)` | Sign EIP-712 typed data |
| `sign_and_send(wallet, chain, tx_hex, index?, rpc_url?, vault_path?)` | Sign and broadcast a transaction |

All operations default to the vault root at `~/.ows/` unless a custom `vault_path` is provided.

## Security Model

- Wallet metadata is stored on disk.
- Mnemonics and private keys are stored in the OS keyring.
- Signing happens inside the caller process today, using secret material fetched on demand.
- Applications do not need to manage secret prompts or encrypted wallet envelopes for new wallets.

This keeps the public API small and makes the storage model the same across CLI, Node, and Python.
