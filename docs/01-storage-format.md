# 01 - Storage Format

> How OWS stores wallet metadata on disk while keeping wallet secrets in the OS keyring.

## Implementation Status

| Feature | Status | Notes |
|---|---|---|
| Vault directory (`~/.ows/wallets/`) | Done | `ows-lib/src/vault.rs` |
| Wallet file format (`ows_version = 3`) | Done | `ows-core/src/wallet_file.rs` |
| Filesystem permissions (700 dirs, 600 files) | Done | `ows-lib/src/vault.rs` |
| OS keyring-backed secret storage | Done | `ows-lib/src/secret_store.rs` |
| Permission verification on startup | Partial | Warns but does not refuse to operate |
| Audit log (`~/.ows/logs/audit.jsonl`) | Done | `ows-cli/src/audit.rs` |
| Legacy embedded `crypto` field | Legacy input only | New wallets do not write it |

## Design Decision

**OWS stores wallet metadata in JSON files and stores secret material in the OS keyring.**

This splits the wallet into two parts:

- A metadata file in `~/.ows/wallets/` that is easy to enumerate, rename, and inspect safely.
- A keyring entry that holds the mnemonic or private key material and is protected by the host OS account.

### Why This Approach

| Approach | Pros | Cons |
|---|---|---|
| Raw secrets in env vars | Simple | Secrets leak into logs, process state, and crash output |
| Encrypted self-contained wallet files | Portable | Keeps the most sensitive bytes on disk and requires extra secret-unlock plumbing |
| Full wallet blob in OS keyring | Strong local protection | Harder to enumerate and back up; keyring payload size varies by platform |
| **Metadata file + keyring secret** | Good UX, clear indexing, small keyring entries | Backup/export must be explicit |

## Vault Layout

```
~/.ows/
├── config.json
├── wallets/
│   ├── <wallet-id>.json
│   └── ...
└── logs/
    └── audit.jsonl
```

The wallet file is the source of truth for metadata. The keyring is the source of truth for secret material.

### Filesystem Permissions

```
~/.ows/                  drwx------  (700)
~/.ows/wallets/          drwx------  (700)
~/.ows/wallets/*.json    -rw-------  (600)
~/.ows/logs/             drwx------  (700)
~/.ows/logs/audit.jsonl  -rw-------  (600)
~/.ows/config.json       -rw-------  (600)
```

## Wallet File Format

Each wallet is stored as a single metadata file:

```json
{
  "ows_version": 3,
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "name": "agent-treasury",
  "created_at": "2026-03-21T10:30:00Z",
  "accounts": [
    {
      "account_id": "eip155:8453:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "address": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "chain_id": "eip155:8453",
      "derivation_path": "m/44'/60'/0'/0/0"
    }
  ],
  "secret_ref": "wallet:v1:8cc95b9db1c68f74:3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "key_type": "mnemonic",
  "metadata": {}
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `ows_version` | integer | yes | Schema version. New wallets use `3`. |
| `id` | string | yes | UUID v4 wallet identifier |
| `name` | string | yes | Human-readable wallet name |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `accounts` | array | yes | Derived account metadata |
| `secret_ref` | string | yes | Reference used to locate the keyring entry |
| `key_type` | string | yes | `mnemonic` or `private_key` |
| `metadata` | object | no | Optional future metadata |

New wallets MUST NOT serialize the legacy `crypto` field.

## Secret References

OWS stores one keyring entry per wallet. The reference format is:

```text
wallet:v1:<vault_scope>:<wallet_id>
```

- `vault_scope` is derived from the vault path so two different vault roots do not collide.
- `wallet_id` keeps the entry stable across wallet renames.

## Keyring Payload

The keyring entry stores a small JSON record:

```json
{
  "version": 1,
  "wallet_id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "key_type": "mnemonic",
  "payload": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}
```

`payload` contains:

- The mnemonic phrase when `key_type = "mnemonic"`.
- A JSON string with both curve keys when `key_type = "private_key"`.

Example private-key payload:

```json
{
  "version": 1,
  "wallet_id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "key_type": "private_key",
  "payload": "{\"secp256k1\":\"4c0883...\",\"ed25519\":\"9d61b1...\"}"
}
```

## Operational Notes

- Listing wallets only reads metadata files.
- Signing and export first resolve `secret_ref`, then fetch the secret from the OS keyring.
- Deleting a wallet removes both the metadata file and the keyring entry.
- Wallet files are no longer self-contained backups. Use `export_wallet` or `ows wallet export` when you need a portable backup.
