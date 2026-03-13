# 01 - Storage Format

> How wallets are encrypted, structured, and stored on the local filesystem.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Vault directory (`~/.ows/wallets/`) | Done | `ows-lib/src/vault.rs` |
| Wallet file format (OWS envelope over Keystore v3) | Done | `ows-core/src/wallet_file.rs` |
| Filesystem permissions (700 dirs, 600 files) | Done | `ows-lib/src/vault.rs` |
| Permission verification on startup | Partial | Warns but does not refuse to operate |
| Audit log (`~/.ows/logs/audit.jsonl`) | Done | `ows-cli/src/audit.rs` |
| Crypto object (AES-256-GCM + scrypt) | Done | `ows-signer/src/crypto.rs` |
| Backward compat (Keystore v3 import) | Not started | No v3 import/re-wrap logic |
| `~/.ows/keys/` directory + API key files | Not started | No API key system |
| `~/.ows/policies/` directory + policy files | Not started | No policy system |
| `~/.ows/plugins/` directory | Not started | Plugins are hardcoded |
| Passphrase 12-char minimum enforcement | Not started | No validation at creation time |

## Design Decision

**OWS uses an extended Ethereum Keystore v3 format with per-chain type adaptations, stored in a well-known directory with strict filesystem permissions.**

### Why This Approach

We evaluated four storage strategies:

| Approach | Pros | Cons |
|---|---|---|
| Raw private keys in env vars | Simple | Catastrophically insecure; keys leak into logs, process lists, LLM contexts |
| Cloud KMS (Privy, Turnkey) | Strong security, TEE-backed | Requires network; not local-first; vendor lock-in |
| OS keychain (macOS Keychain, Windows DPAPI) | OS-level encryption | Not portable across platforms; no standard multi-key format |
| **Encrypted JSON keystore** | Portable, proven, auditable, local-first | Must protect against brute-force; requires passphrase management |

The Ethereum Keystore v3 format has been battle-tested since 2015, is implemented in every major Web3 library, and provides strong encryption with configurable KDF parameters. OWS extends it to support non-EVM chains while maintaining backward compatibility with existing EVM tooling.

## Vault Directory Structure

```
~/.ows/
├── config.json                    # Global configuration
├── wallets/
│   ├── <wallet-id>.json           # Encrypted wallet file (one per wallet)
│   └── ...
├── keys/
│   ├── <key-id>.json              # API key definition (one per key)
│   └── ...
├── policies/
│   ├── <policy-id>.json           # Policy definition
│   └── ...
├── plugins/
│   ├── <chain-type>/              # Chain-specific plugins
│   │   ├── signer.js              # Signing implementation
│   │   └── builder.js             # Transaction builder
│   └── ...
└── logs/
    └── audit.jsonl                # Append-only audit log
```

### Filesystem Permissions

```
~/.ows/                  drwx------  (700)
~/.ows/wallets/          drwx------  (700)
~/.ows/wallets/*.json    -rw-------  (600)
~/.ows/keys/             drwx------  (700)
~/.ows/keys/*.json       -rw-------  (600)
~/.ows/policies/         drwxr-xr-x  (755)
~/.ows/config.json       -rw-------  (600)
~/.ows/logs/audit.jsonl  -rw-------  (600)
```

The `wallets/` directory and its contents MUST be readable only by the owner. Implementations MUST verify permissions on startup and refuse to operate if the vault directory is world-readable or group-readable.

## Wallet File Format

Each wallet is stored as a single JSON file extending the Ethereum Keystore v3 structure:

```json
{
  "ows_version": 1,
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "name": "agent-treasury",
  "created_at": "2026-02-27T10:30:00Z",
  "chain_type": "evm",
  "accounts": [
    {
      "account_id": "eip155:8453:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "address": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
      "chain_id": "eip155:8453",
      "derivation_path": "m/44'/60'/0'/0/0"
    }
  ],
  "crypto": {
    "cipher": "aes-256-gcm",
    "cipherparams": {
      "iv": "6087dab2f9fdbbfaddc31a90"
    },
    "ciphertext": "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
    "auth_tag": "3c5d8c2f1a4b6e9d0f2a5c8b",
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "r": 8,
      "p": 1,
      "salt": "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"
    }
  },
  "key_type": "mnemonic",
  "metadata": {}
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `ows_version` | integer | yes | Schema version (currently `1`) |
| `id` | string | yes | UUID v4 wallet identifier |
| `name` | string | yes | Human-readable wallet name |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `chain_type` | string | yes | Primary chain type: `evm`, `solana`, `tron`, `cosmos`, `bitcoin` |
| `accounts` | array | yes | Derived accounts (see Account object) |
| `crypto` | object | yes | Encryption parameters (see Crypto object) |
| `key_type` | string | yes | `mnemonic` (BIP-39) or `private_key` (raw) |
| `metadata` | object | no | Extensible metadata |

## API Key File Format

Each API key is stored as a JSON file in `~/.ows/keys/`:

```json
{
  "id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "name": "claude-agent",
  "token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "created_at": "2026-02-27T10:30:00Z",
  "wallet_ids": ["3198bc9c-6672-5ab3-d995-4942343ae5b6"],
  "policy_ids": ["spending-limit-01", "safe-agent-policy"],
  "expires_at": null
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | UUID v4 key identifier |
| `name` | string | yes | Human-readable label for the key |
| `token_hash` | string | yes | SHA-256 hex digest of the raw token. The raw token (`ows_key_...`) is shown once at creation and never stored. |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `wallet_ids` | array | yes | Wallet IDs this key is authorized to access |
| `policy_ids` | array | yes | Policy IDs evaluated on every request made with this key |
| `expires_at` | string | no | ISO 8601 expiry timestamp. `null` means no expiry. |

The `keys/` directory and its contents use the same strict permissions as `wallets/` (`700` for the directory, `600` for files) because the `token_hash` must be protected against local reads.

### Crypto Object

The `crypto` object follows Keystore v3 conventions with two upgrades:

1. **AES-256-GCM** is the default cipher (upgraded from AES-128-CTR). GCM provides authenticated encryption, eliminating the need for a separate MAC field.
2. **scrypt** remains the recommended KDF with the same parameter semantics. PBKDF2-SHA256 is an acceptable alternative for resource-constrained environments.

| Field | Type | Description |
|---|---|---|
| `cipher` | string | `aes-256-gcm` (recommended) or `aes-128-ctr` (v3 compat) |
| `cipherparams.iv` | string | Hex-encoded initialization vector |
| `ciphertext` | string | Hex-encoded encrypted key material |
| `auth_tag` | string | Hex-encoded GCM auth tag (only for `aes-256-gcm`) |
| `kdf` | string | `scrypt` (recommended) or `pbkdf2` |
| `kdfparams` | object | KDF-specific parameters |

For `aes-128-ctr` (backward compat), a `mac` field with `keccak-256(dk[16..31] ++ ciphertext)` is required, following the Keystore v3 spec.

### What Gets Encrypted

The `ciphertext` contains the encrypted form of either:

- **BIP-39 mnemonic entropy** (128 or 256 bits) — when `key_type` is `mnemonic`. The mnemonic can derive keys for any supported chain via BIP-44 derivation paths.
- **Raw private key** (32 bytes for secp256k1/ed25519) — when `key_type` is `private_key`. Used for imported single-chain keys.

Storing the mnemonic (rather than individual private keys) enables a single encrypted blob to derive accounts across multiple chains and indices.

## Passphrase Management

The vault passphrase is used to derive the encryption key via the configured KDF. OWS does NOT define how the passphrase is obtained — this is deliberately left to the implementation:

- **Interactive CLI**: Prompt at first use, optionally cache in OS keychain for a session
- **Agent/daemon mode**: Read from a file descriptor (RECOMMENDED), an environment variable (`OWS_PASSPHRASE`), or a hardware token. Environment variables are the least secure option — they are readable via `/proc/[pid]/environ` by same-user processes and leak into crash dumps and child process environments. Implementations using `OWS_PASSPHRASE` MUST clear it from the process environment immediately after reading.
- **Unlocked mode** (development only): A config flag that uses a well-known passphrase — MUST produce a visible warning

The passphrase MUST be at least 12 characters. Implementations SHOULD enforce this at wallet creation time.

## Audit Log

All signing operations are appended to `~/.ows/logs/audit.jsonl`:

```json
{
  "timestamp": "2026-02-27T10:35:22Z",
  "wallet_id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "operation": "sign_transaction",
  "chain_id": "eip155:8453",
  "to": "0x4B0897b0513fdC7C541B6d9D7E929C4e5364D2dB",
  "value": "1000000",
  "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "policy_result": "allow",
  "tx_hash": "0xabc123..."
}
```

The audit log is append-only. Implementations MUST NOT allow deletion or modification of existing entries. Log rotation is permitted (e.g., monthly archives).

## Backward Compatibility

Any valid Ethereum Keystore v3 file can be imported into an OWS vault. The importer:

1. Reads the v3 JSON
2. Wraps it in the OWS envelope (adds `ows_version`, `name`, `chain_type: "evm"`, `accounts`)
3. Optionally re-encrypts with AES-256-GCM

Exported OWS wallets with `cipher: "aes-128-ctr"` and `key_type: "private_key"` are valid Keystore v3 files (minus the OWS envelope fields, which are ignored by v3 parsers).

## References

- [Ethereum Web3 Secret Storage Definition](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
- [BIP-39: Mnemonic Seed Phrases](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [NIST SP 800-38D: GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Privy: Low-Level Key Management](https://privy.io/blog/powering-programmable-wallets-with-low-level-key-management)
