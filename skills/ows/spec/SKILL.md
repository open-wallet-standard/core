---
name: ows-spec
description: Complete OWS specification — storage format, signing interface, policy engine, agent access, key isolation, wallet lifecycle, supported chains, and conformance requirements. Use when implementing against, auditing, or reasoning about the Open Wallet Standard.
version: 1.0.0
metadata:
  openclaw:
    emoji: "\U0001F4DC"
    homepage: https://openwallet.sh
---

# OWS — Open Wallet Standard Specification

OWS is a local-first wallet specification defining encrypted storage, multi-chain signing, pre-signing policy enforcement, and wallet lifecycle management. Keys stay encrypted at rest and are decrypted only for the duration of a signing operation, then immediately wiped.

This document is a complete, self-contained distillation of the OWS normative spec (docs 00–08). For edge cases, defer to the numbered docs in `docs/`.

## When to use

Use this skill when you need to:

- Implement or extend an OWS-conforming wallet, signer, or policy engine
- Audit an implementation for spec compliance
- Write or review policy definitions (declarative or executable)
- Reason about the credential model, encryption schemes, or signing flows
- Add a new chain family to an OWS implementation
- Review or write conformance tests
- Understand the security model and threat mitigations

For **using** OWS (creating wallets, signing, SDK calls), use the `ows` skill instead.

---

## Document Hierarchy

Normative core: `01-storage-format`, `02-signing-interface`, `03-policy-engine`, `06-wallet-lifecycle`, `07-supported-chains`, `08-conformance-and-security`.

Optional profiles: `04-agent-access-layer`, `05-key-isolation`.

Non-normative: `quickstart`, `sdk-cli`, `sdk-node`, `sdk-python`, `policy-engine-implementation`.

If a normative doc conflicts with a reference implementation doc, the normative doc wins.

RFC 2119 keywords (MUST, SHOULD, MAY) apply in normative documents only. Examples, CLI syntax, package names, and RPC URLs are informative.

---

## Storage Format

### Vault Structure

```
~/.ows/
├── config.json                    (600)
├── wallets/<wallet-id>.json       (700/600) — encrypted wallet files
├── keys/<key-id>.json             (700/600) — API key files with encrypted wallet secrets
├── policies/<policy-id>.json      (755/644) — policy definitions (not secret)
└── logs/audit.jsonl               (600)     — append-only audit log
```

Implementations MUST verify `wallets/` and `keys/` are not world-readable or group-readable on startup.

### Wallet File (v2)

```json
{
  "ows_version": 2,
  "id": "UUID v4",
  "name": "human-readable name",
  "created_at": "ISO 8601",
  "accounts": [
    {
      "account_id": "CAIP-10 (chain_id:address)",
      "address": "chain-native address",
      "chain_id": "CAIP-2",
      "derivation_path": "BIP-44 path"
    }
  ],
  "crypto": {
    "cipher": "aes-256-gcm",
    "cipherparams": { "iv": "hex" },
    "ciphertext": "hex — encrypted mnemonic entropy or raw private key",
    "auth_tag": "hex",
    "kdf": "scrypt",
    "kdfparams": { "dklen": 32, "n": 65536, "r": 8, "p": 1, "salt": "hex 32 bytes" }
  },
  "key_type": "mnemonic | private_key",
  "metadata": {}
}
```

- `ciphertext` contains BIP-39 mnemonic entropy (128/256 bits) when `key_type` is `mnemonic`, or a raw 32-byte private key when `key_type` is `private_key`.
- AES-256-GCM is the default cipher (upgraded from Keystore v3's AES-128-CTR). GCM provides authenticated encryption — no separate MAC field needed.
- scrypt minimum work factor: N=2^16, r=8, p=1.
- Passphrase MUST be at least 12 characters.
- Implementations MUST reject unknown required schema fields and unknown schema versions.
- Implementations MUST preserve unknown fields during non-destructive updates.

### API Key File

```json
{
  "id": "UUID v4",
  "name": "human-readable label",
  "token_hash": "SHA-256 hex of raw token (ows_key_<64 hex>)",
  "created_at": "ISO 8601",
  "wallet_ids": ["wallet UUIDs this key can access"],
  "policy_ids": ["policy IDs evaluated on every request"],
  "expires_at": "ISO 8601 | null",
  "wallet_secrets": {
    "<wallet-id>": {
      "cipher": "aes-256-gcm",
      "cipherparams": { "iv": "hex" },
      "ciphertext": "hex — mnemonic re-encrypted under HKDF(token)",
      "auth_tag": "hex",
      "kdf": "hkdf-sha256",
      "kdfparams": { "dklen": 32, "salt": "hex 32 bytes", "info": "ows-api-key-v1" }
    }
  }
}
```

Raw token format: `ows_key_<64 hex chars>` (256-bit random). Shown once at creation, only the SHA-256 hash is stored. Revoking = deleting the key file.

### Policy File

```json
{
  "id": "unique string",
  "name": "human-readable name",
  "version": 1,
  "created_at": "ISO 8601",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "expires_at", "timestamp": "ISO 8601" }
  ],
  "executable": "/absolute/path/to/script | null",
  "config": { "static config passed to executable via PolicyContext.policy_config" },
  "action": "deny"
}
```

A policy MUST have at least one of `rules` or `executable`.

### Audit Log

Append-only JSONL. Required fields: `timestamp`, `wallet_id`, `operation`. Operations include `create_wallet`, `import_wallet`, `export_wallet`, `broadcast_transaction`, `delete_wallet`, `rename_wallet`, `policy_evaluated`, `policy_denied`. MUST NOT contain passphrases, tokens, mnemonics, or private keys.

### Backward Compatibility

Valid Ethereum Keystore v3 files can be imported. OWS wallets with `aes-128-ctr` cipher and `private_key` key_type are valid v3 files (minus OWS envelope fields).

---

## Signing Interface

### sign(request) → SignResult

Signs a transaction without broadcasting.

```
SignRequest { walletId, chainId (CAIP-2), transactionHex (hex-encoded serialized bytes) }
SignResult  { signature (hex), recoveryId? (number, secp256k1 only) }
```

Flow:
1. Resolve wallet and chain
2. Authenticate: owner (passphrase) or agent (API token)
3. If agent: verify wallet scope, evaluate all attached policies
4. If owner: skip policy evaluation
5. Decrypt key material
6. Sign via chain-specific signer
7. Wipe key material
8. Return signature

### signAndSend(request) → SignAndSendResult

Signs and broadcasts. Same auth/policy checks as sign. Returns `{ transactionHash }`. `rpcUrl` is an optional endpoint override.

### signMessage(request) → SignMessageResult

Signs arbitrary messages with chain-specific conventions:
- **EVM**: EIP-191 (`personal_sign`) or EIP-712 (`eth_signTypedData_v4`)
- **Solana**: Ed25519 over raw bytes
- **Sui**: Intent-prefixed (scope=3) BLAKE2b-256 digest, Ed25519
- **Cosmos**: ADR-036 off-chain signing
- **Filecoin**: Blake2b-256 hash then secp256k1

```
SignMessageRequest { walletId, chainId, message (string|bytes), encoding? (utf8|hex), typedData? }
SignMessageResult  { signature (hex), recoveryId? }
```

### signTypedData(request) → SignMessageResult

EIP-712 typed structured data (EVM only). Input is a JSON string with `types`, `primaryType`, `domain`, `message`.

### Error Codes

| Code | Meaning |
|---|---|
| WALLET_NOT_FOUND | No wallet with that ID |
| CHAIN_NOT_SUPPORTED | No signer for that chain |
| INVALID_PASSPHRASE | Wrong passphrase |
| INVALID_INPUT | Malformed request |
| CAIP_PARSE_ERROR | Unparseable chain identifier |
| POLICY_DENIED | Rejected by policy engine |
| API_KEY_NOT_FOUND | Token doesn't match any key |
| API_KEY_EXPIRED | Key past its expires_at |

Implementations MUST NOT rewrite a denial into a success or silent fallback.

---

## Policy Engine

### Credential-Based Access Model

```
sign(wallet, chain, tx, credential)
                           │
              ┌────────────┴────────────┐
         passphrase                ows_key_...
              │                         │
         owner mode                agent mode
         no policy eval            all attached policies evaluated
         scrypt decrypt            HKDF decrypt
```

The credential itself determines the tier. No bypass flags. Owner = passphrase. Agent = token. Different agents get different tokens with different policies.

### API Key Cryptography

Creation flow:
1. Owner enters passphrase → scrypt decrypts wallet mnemonic
2. Generate random token: `ows_key_<64 hex>`
3. Generate random salt
4. `HKDF-SHA256(salt, token, "ows-api-key-v1", 32)` → AES-256-GCM key
5. Encrypt mnemonic copy under that key
6. Store key file with `token_hash: SHA256(token)`, policy IDs, encrypted mnemonic
7. Display token once

Agent signing flow:
1. Detect `ows_key_` prefix → agent mode
2. `SHA256(token)` → look up key file
3. Check `expires_at`, verify wallet in `wallet_ids` scope
4. Load policies from `policy_ids`
5. Build PolicyContext, evaluate all policies (AND semantics, short-circuit on first deny)
6. If denied → POLICY_DENIED error (key material never touched)
7. `HKDF(token)` → decrypt mnemonic from `wallet_secrets`
8. HD-derive chain key → sign → zeroize → return signature

### Declarative Rules

Evaluated in-process (microseconds):

- **`allowed_chains`**: `{ "type": "allowed_chains", "chain_ids": ["eip155:8453"] }` — denies if chain not in list.
- **`expires_at`**: `{ "type": "expires_at", "timestamp": "ISO 8601" }` — denies if current time is past timestamp.

Unknown rule types MUST be denied (fail closed).

### Custom Executable Policies

For value caps, recipient allowlists, simulation, or any complex logic.

Protocol: `echo '<PolicyContext JSON>' | /path/to/executable`
- MUST write `{"allow": true}` or `{"allow": false, "reason": "..."}` to stdout
- Non-zero exit → deny
- Invalid JSON → deny
- No exit within 5 seconds → kill + deny
- Executable not found → deny

When a policy has both `rules` and `executable`: declarative rules evaluate first as a fast pre-filter. Executable only runs if rules pass. Both must allow.

### PolicyContext

```json
{
  "chain_id": "CAIP-2",
  "wallet_id": "UUID",
  "api_key_id": "UUID",
  "transaction": {
    "to": "address (EVM parsed)",
    "value": "wei string (EVM parsed)",
    "data": "hex (EVM parsed)",
    "raw_hex": "always present, all chains"
  },
  "spending": {
    "daily_total": "wei string",
    "date": "YYYY-MM-DD"
  },
  "timestamp": "ISO 8601",
  "policy_config": {}
}
```

`transaction` fields beyond `raw_hex` are chain-specific (EVM gets parsed `to`, `value`, `data`). `policy_config` is the static `config` from the policy file.

### Policy Attachment

Policies attach to API keys, not wallets. Multiple policies per key — all must allow (AND semantics).

---

## Agent Access Layer

Implementations may expose OWS through: in-process bindings, local subprocess, local RPC/daemon, or CLI wrappers. All surfaces MUST preserve core semantics.

### Required Capabilities

| Capability | Requirement |
|---|---|
| Wallet selection | MUST identify wallet unambiguously by ID or stable alias |
| Chain selection | MUST resolve to canonical CAIP-2 identifier before signing |
| Credential handling | MUST distinguish owner credentials from API tokens without ambiguity |
| Policy enforcement | MUST evaluate policies before any token-backed secret is decrypted |
| Error propagation | MUST surface errors without rewriting denial into success |
| Secret handling | MUST NOT expose decrypted key material unless explicit export is invoked |

### Access Profiles

- **Profile A (In-Process)**: Caller links directly. MUST zeroize secrets on completion.
- **Profile B (Subprocess)**: Spawns OWS child per operation. MUST authenticate input, enforce policy before decryption.
- **Profile C (Local Service)**: Loopback-only daemon. MUST bind only to local interfaces. MUST authenticate callers.

If multiple access layers exist, all MUST agree on wallet lookup, policy evaluation order, error codes, chain normalization, and audit logging.

---

## Key Isolation

### Current Model: In-Process Hardening

Key lifecycle per signing request:
1. Receive sign request
2. If API token: evaluate policies before decryption
3. Derive decryption key (scrypt for passphrase, HKDF for token)
4. Decrypt into hardened memory (mlock'd)
5. Derive chain-specific signing key
6. Sign
7. Zeroize: mnemonic, derived key, KDF output, signing key
8. Return signature only

### Threat Mitigations

| Threat | Mitigation |
|---|---|
| Agent misuses wallet | API tokens scope access + policy checks before decryption |
| Key leaked to logs | OWS never logs key material |
| Core dump | Process hardening disables core dumps where supported |
| Swap file exposure | mlock() where available |
| Passphrase brute force | scrypt minimum N=2^16 |

### Key Cache (Optional)

For batch performance. TTL ≤30s (5s recommended), max 32 entries, LRU eviction, mlock'd, zeroized on eviction, cleared on SIGTERM/SIGINT/SIGHUP.

---

## Wallet Lifecycle

### Creation

Generate BIP-39 mnemonic → derive master seed (PBKDF2) → derive accounts per chain via BIP-44 → encrypt mnemonic → write wallet file → wipe all secrets. Mnemonic is never returned to caller.

### Import Formats

Supported: BIP-39 mnemonic, raw private key (hex), Ethereum Keystore v3, WIF (Bitcoin), Solana keypair JSON, Sui keystore JSON.

Private key imports generate accounts for all 8 chains: the provided key's curve is used for matching chains, a random key is generated for the other curve.

### Export

Requires explicit confirmation. Mnemonic wallets return the phrase. Private key wallets return `{"secp256k1":"hex","ed25519":"hex"}`.

### Deletion

Securely overwrites wallet file with random bytes before unlinking. Removes wallet ID from all API keys' `wallet_ids`. Logs to audit.

### Recovery

From mnemonic: derive accounts, scan for balances using BIP-44 gap limit of 20 consecutive empty addresses.

---

## Supported Chains

OWS uses CAIP-2 chain identifiers and CAIP-10 account identifiers throughout. Shorthand aliases MUST be resolved to full CAIP-2 IDs before processing and MUST NOT appear in wallet files, policy files, or audit logs.

| Family | Curve | Derivation Path | Address Format | CAIP-2 Namespace |
|---|---|---|---|---|
| EVM | secp256k1 | `m/44'/60'/0'/0/{i}` | EIP-55 checksummed hex | `eip155` |
| Solana | Ed25519 | `m/44'/501'/{i}'/0'` | Base58 public key | `solana` |
| Bitcoin | secp256k1 | `m/84'/0'/0'/0/{i}` | Bech32 native segwit | `bip122` |
| Cosmos | secp256k1 | `m/44'/118'/0'/0/{i}` | Bech32 | `cosmos` |
| Tron | secp256k1 | `m/44'/195'/0'/0/{i}` | Base58Check | `tron` |
| TON | Ed25519 | `m/44'/607'/{i}'` | Base64url wallet v5r1 | `ton` |
| Sui | Ed25519 | `m/44'/784'/{i}'/0'/0'` | 0x + BLAKE2b-256 hex | `sui` |
| Spark | secp256k1 | `m/84'/0'/0'/0/{i}` | spark: + compressed pubkey | `spark` |
| Filecoin | secp256k1 | `m/44'/461'/0'/0/{i}` | f1 + base32(blake2b-160) | `fil` |

Known mainnet IDs: `eip155:1` (Ethereum), `eip155:8453` (Base), `eip155:137` (Polygon), `eip155:42161` (Arbitrum), `eip155:10` (Optimism), `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`, `bip122:000000000019d6689c085ae165831e93`, `cosmos:cosmoshub-4`, `tron:mainnet`, `ton:mainnet`, `sui:mainnet`, `spark:mainnet`, `fil:mainnet`.

A single BIP-39 mnemonic derives accounts across all families. The wallet file stores the encrypted mnemonic; the signer derives the appropriate key per chain.

### Adding a New Chain

Define: canonical CAIP-2 identifier, derivation path + coin type, address encoding, signing behavior per `02-signing-interface`, transaction serialization rules. No changes to OWS core required.

---

## Conformance and Security

### Conformance Claims

Format: `OWS <profiles>` (e.g., `OWS Storage + Signing + Policy + EVM Chain Profile`). MUST NOT claim general compliance for partial implementations.

### Interoperability

Conforming implementations MUST agree on: wallet file parsing, API key resolution by token hash, policy evaluation results for identical PolicyContext, chain/account identifier preservation.

### Security Requirements

- MUST decrypt secrets only for operation duration, then zeroize
- MUST NOT log secrets, tokens, mnemonics, or private keys
- MUST verify API token scope and policies before decryption
- MUST evaluate policy rules deterministically
- MUST deny on executable policy failure, malformed output, or timeout
- MUST NOT provide fallback paths bypassing policy evaluation
- Audit logs MUST be append-only

---

## Specification Versioning

- Wallet file schema: `ows_version = 2`
- Policy schema: `version = 1`

Implementations MUST reject unknown required schema fields and unknown schema versions. MAY accept older versions if compatibility is documented.

## Extension Rules

- New chains MAY be added with: stable CAIP-2 namespace, deterministic derivation path, address encoding rule.
- Policy engines MAY add namespaced rule types. MUST reject unknown unnamespaced types.
- Files MAY include extra metadata fields. Implementations MUST preserve unknown fields on non-destructive updates.
- Extensions MUST NOT redefine existing required fields.
