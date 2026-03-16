# 06 - Agent Access Layer

> How AI agents, CLI tools, and applications access OWS wallets through native language bindings.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| `generate_mnemonic(words?)` | Done | 12 or 24 words |
| `derive_address(mnemonic, chain, index?)` | Done | |
| `create_wallet(name, chain, passphrase, ...)` | Done | |
| `import_wallet_mnemonic(...)` | Done | |
| `import_wallet_private_key(...)` | Done | |
| `list_wallets(vault_path?)` | Done | |
| `get_wallet(name_or_id, vault_path?)` | Done | |
| `delete_wallet(name_or_id, vault_path?)` | Done | |
| `export_wallet(name_or_id, passphrase, ...)` | Done | |
| `rename_wallet(name_or_id, new_name, ...)` | Done | |
| `sign_transaction(...)` | Done | |
| `sign_message(...)` | Done | |
| `sign_and_send(...)` | Done | |
| Node.js NAPI bindings | Done | `bindings/node/src/lib.rs` |
| Python PyO3 bindings | Done | `bindings/python/src/lib.rs` |
| API key scoping (agent sees only permitted wallets) | Not started | No API key system |
| Policy evaluation on agent requests | Not started | No policy engine |
| MCP server | Not started | |
| Audit logging from bindings (not just CLI) | Not started | Only CLI logs to audit |

## Design Decision

**OWS exposes wallet operations through native language bindings backed by the core Rust implementation. Bindings call directly into the `ows-lib` crate via FFI — no HTTP server or subprocess is required. They are compiled native modules that run in-process.**

## Native Language Bindings

### Node.js (NAPI)

```bash
npm install @open-wallet-standard/core
```

```typescript
import { createWallet, listWallets, signMessage, signTransaction, signAndSend } from "@open-wallet-standard/core";

// Create a wallet
const wallet = createWallet("agent-treasury", "evm", "my-passphrase");
// => { id, name, chain, address, derivation_path, created_at }

// List all wallets
const wallets = listWallets();

// Sign a message
const sig = signMessage("agent-treasury", "evm", "hello", "my-passphrase");
// => { signature, recoveryId? }

// Sign and broadcast a transaction
const result = signAndSend("agent-treasury", "evm", "<tx-hex>", "my-passphrase");
// => { txHash }
```

### Python (PyO3)

```bash
pip install open-wallet-standard
```

```python
from open_wallet_standard import create_wallet, list_wallets, sign_message, sign_transaction, sign_and_send

# Create a wallet
wallet = create_wallet("agent-treasury", "evm", "my-passphrase")
# => {"id", "name", "chain", "address", "derivation_path", "created_at"}

# List all wallets
wallets = list_wallets()

# Sign a message
sig = sign_message("agent-treasury", "evm", "hello", "my-passphrase")
# => {"signature", "recovery_id"}

# Sign and broadcast a transaction
result = sign_and_send("agent-treasury", "evm", "<tx-hex>", "my-passphrase")
# => {"tx_hash"}
```

### Available Functions

Both bindings expose the same 13 functions:

| Function | Description |
|---|---|
| `generate_mnemonic(words?)` | Generate a BIP-39 mnemonic (12 or 24 words) |
| `derive_address(mnemonic, chain, index?)` | Derive a chain-specific address from a mnemonic |
| `create_wallet(name, chain, passphrase, words?, vault_path?)` | Create a new wallet (generates mnemonic, encrypts, saves) |
| `import_wallet_mnemonic(name, chain, mnemonic, passphrase, index?, vault_path?)` | Import a wallet from a mnemonic |
| `import_wallet_private_key(name, chain, key_hex, passphrase, vault_path?, secp256k1_key?, ed25519_key?)` | Import a wallet from a raw private key (or explicit per-curve keys) |
| `list_wallets(vault_path?)` | List all wallets in the vault |
| `get_wallet(name_or_id, vault_path?)` | Get a single wallet by name or ID |
| `delete_wallet(name_or_id, vault_path?)` | Delete a wallet |
| `export_wallet(name_or_id, passphrase, vault_path?)` | Export a wallet's secret (mnemonic or private key) |
| `rename_wallet(name_or_id, new_name, vault_path?)` | Rename a wallet |
| `sign_transaction(wallet, chain, tx_hex, passphrase, index?, vault_path?)` | Sign a transaction |
| `sign_message(wallet, chain, message, passphrase, encoding?, index?, vault_path?)` | Sign a message |
| `sign_and_send(wallet, chain, tx_hex, passphrase, index?, rpc_url?, vault_path?)` | Sign and broadcast a transaction |

All functions operate on the default vault (`~/.ows/`) unless a custom `vault_path` is provided. The passphrase is used to decrypt wallet key material for signing operations.

> **Note:** Because the bindings run in-process, key material is decrypted within the application's address space. For use cases where key isolation is critical, consider running OWS in a separate subprocess.

## Agent Interaction Example

Here's how an AI agent interacts with OWS through the bindings using an API key. The API key scopes the agent to specific wallets and policies.

```
Agent: "I need to send 0.01 ETH to 0x4B08... on Base"

1. Agent calls list_wallets to find available wallets
   → Returns only wallets in the API key's scope
   → [{ id: "3198bc9c-...", name: "agent-treasury", ... }]

2. Agent calls sign_and_send to execute
   → API key verified: wallet is in key's scope
   → Policy engine evaluates the API key's attached policies
   → Signing enclave decrypts key, signs, wipes
   → Transaction broadcast to Base RPC
   → Returns: { tx_hash: "0xabc..." }
```

At no point does the agent see the private key. The API key determines which wallets the agent can access, and the policies attached to the key constrain what operations are permitted.

## References

- [Privy Server Wallet REST API](https://docs.privy.io/guide/server-wallets/create)
