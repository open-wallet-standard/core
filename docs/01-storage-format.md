# Storage Format

> The storage format is the core of the OWS standard. It defines how wallets, API keys, and policies are encrypted and stored on the local filesystem. Everything else — signing, policy enforcement, language bindings — operates on these files.

OWS extends the Ethereum Keystore v3 format with per-chain type adaptations, stored in a well-known directory with strict filesystem permissions. Any implementation that reads and writes these files correctly is a conforming OWS implementation.

## Vault Directory Structure

```
~/.ows/
├── config.json                    # Global configuration
├── wallets/
│   ├── <wallet-id>.json           # Encrypted wallet file (one per wallet)
│   └── ...
├── keys/
│   ├── <key-id>.json              # API key + encrypted wallet secrets (one per key)
│   └── ...
├── policies/
│   ├── <policy-id>.json           # Policy definition (declarative rules and/or executable)
│   └── ...
└── logs/
    └── audit.jsonl                # Append-only audit log
```

### Filesystem Permissions

```
~/.ows/                       drwx------  (700)
~/.ows/wallets/               drwx------  (700)
~/.ows/wallets/*.json         -rw-------  (600)
~/.ows/keys/                  drwx------  (700)
~/.ows/keys/*.json            -rw-------  (600)
~/.ows/policies/              drwxr-xr-x  (755)
~/.ows/policies/*.json        -rw-r--r--  (644)
~/.ows/config.json            -rw-------  (600)
~/.ows/logs/audit.jsonl       -rw-------  (600)
```

The `wallets/` and `keys/` directories contain encrypted secrets and MUST be readable only by the owner. Implementations MUST verify permissions on startup and refuse to operate if these directories are world-readable or group-readable.

The `policies/` directory uses relaxed permissions (755/644) because policy files are not secret — they contain rule definitions and paths to executables, not key material.

## Wallet File Format

Each wallet is stored as a single JSON file extending the Ethereum Keystore v3 structure:

```json
{
  "ows_version": 2,
  "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "name": "agent-treasury",
  "created_at": "2026-02-27T10:30:00Z",
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
      "n": 65536,
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
| `ows_version` | integer | yes | Schema version (currently `2`) |
| `id` | string | yes | UUID v4 wallet identifier |
| `name` | string | yes | Human-readable wallet name |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `accounts` | array | yes | Derived accounts (see Account object) |
| `crypto` | object | yes | Encryption parameters (see Crypto object) |
| `key_type` | string | yes | `mnemonic` (BIP-39) or `private_key` (raw) |
| `metadata` | object | no | Extensible metadata |

## API Key File Format

Each API key is stored as a JSON file in `~/.ows/keys/`. The key file contains metadata, policy attachments, and **encrypted copies of wallet secrets** re-encrypted under the API token (see [Policy Engine](03-policy-engine) for the full cryptographic design).

```json
{
  "id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "name": "claude-agent",
  "token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "created_at": "2026-03-22T10:30:00Z",
  "wallet_ids": ["3198bc9c-6672-5ab3-d995-4942343ae5b6"],
  "policy_ids": ["spending-limit", "base-only"],
  "expires_at": null,
  "wallet_secrets": {
    "3198bc9c-6672-5ab3-d995-4942343ae5b6": {
      "cipher": "aes-256-gcm",
      "cipherparams": { "iv": "a1b2c3d4e5f6a7b8c9d0e1f2" },
      "ciphertext": "...",
      "auth_tag": "...",
      "kdf": "hkdf-sha256",
      "kdfparams": { "dklen": 32, "salt": "...", "info": "ows-api-key-v1" }
    }
  }
}
```

### Field Definitions

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | UUID v4 key identifier |
| `name` | string | yes | Human-readable label for the key |
| `token_hash` | string | yes | SHA-256 hex digest of the raw token. The raw token (`ows_key_<64 hex chars>`) is shown once at creation and never stored. |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `wallet_ids` | array | yes | Wallet IDs this key is authorized to access |
| `policy_ids` | array | yes | Policy IDs evaluated on every request made with this key |
| `expires_at` | string | no | ISO 8601 expiry timestamp. `null` means no expiry. |
| `wallet_secrets` | object | yes | Map of wallet ID → CryptoEnvelope. Each entry is the wallet's decrypted secret re-encrypted under HKDF(token), whether that secret is a mnemonic phrase or private-key JSON. |

The `keys/` directory and its contents use the same strict permissions as `wallets/` (`700` for the directory, `600` for files) because `wallet_secrets` contains encrypted key material and `token_hash` must be protected against local reads.

Revoking an API key means deleting the key file. The encrypted secret copies are destroyed. The original wallet file and other API keys are unaffected.

### Crypto Object

The `crypto` object follows Keystore v3 conventions with two upgrades:

1. **AES-256-GCM** is the default cipher (upgraded from AES-128-CTR). GCM provides authenticated encryption, eliminating the need for a separate MAC field.
2. **scrypt** remains the recommended KDF for wallet files (passphrase-derived). **HKDF-SHA256** is used for API key files (token-derived).

| Field | Type | Description |
|---|---|---|
| `cipher` | string | `aes-256-gcm` (recommended) or `aes-128-ctr` (v3 compat) |
| `cipherparams.iv` | string | Hex-encoded initialization vector |
| `ciphertext` | string | Hex-encoded encrypted key material |
| `auth_tag` | string | Hex-encoded GCM auth tag (only for `aes-256-gcm`) |
| `kdf` | string | `scrypt`, `hkdf-sha256`, or `pbkdf2` |
| `kdfparams` | object | KDF-specific parameters (see below) |

**scrypt kdfparams** (wallet files — passphrase input):

| Field | Type | Description |
|---|---|---|
| `dklen` | integer | Derived key length in bytes (32) |
| `n` | integer | CPU/memory cost parameter (must be power of 2, minimum 2^16) |
| `r` | integer | Block size (8) |
| `p` | integer | Parallelization (1) |
| `salt` | string | Hex-encoded random salt (32 bytes) |

**hkdf-sha256 kdfparams** (API key files — token input):

| Field | Type | Description |
|---|---|---|
| `dklen` | integer | Derived key length in bytes (32) |
| `salt` | string | Hex-encoded random salt (32 bytes) |
| `info` | string | Context string (`"ows-api-key-v1"`) |

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
  "operation": "broadcast_transaction",
  "chain_id": "eip155:8453",
  "details": "tx_hash=0xabc123..."
}
```

Current CLI audit operations include `create_wallet`, `import_wallet`, `export_wallet`, `broadcast_transaction`, `delete_wallet`, and `rename_wallet`.

All fields except `timestamp`, `wallet_id`, and `operation` are optional.

The audit log is append-only. Implementations MUST NOT allow deletion or modification of existing entries. Log rotation is permitted (e.g., monthly archives).

## Backward Compatibility

Any valid Ethereum Keystore v3 file can be imported into an OWS vault. The importer:

1. Reads the v3 JSON
2. Wraps it in the OWS envelope (adds `ows_version`, `name`, `accounts`)
3. Optionally re-encrypts with AES-256-GCM

Exported OWS wallets with `cipher: "aes-128-ctr"` and `key_type: "private_key"` are valid Keystore v3 files (minus the OWS envelope fields, which are ignored by v3 parsers).

## References

- [Ethereum Web3 Secret Storage Definition](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [ERC-2335: BLS12-381 Keystore](https://eips.ethereum.org/EIPS/eip-2335)
- [BIP-39: Mnemonic Seed Phrases](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [NIST SP 800-38D: GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
