# Key Isolation

> Optional deployment guidance for reducing private-key exposure to agents, logs, and local process risks.

This document describes recommended implementation strategies and deployment profiles rather than a single mandatory architecture.

## Current Architecture

```
┌────────────────────────────────────────────┐
│           Agent / CLI / App Process        │
│                                            │
│  1. Build transaction or message           │
│  2. Call OWS signing API                   │
│  3. If credential is `ows_key_...`:        │
│     evaluate attached policies             │
│  4. Decrypt wallet secret in hardened mem  │
│  5. Derive chain-specific signing key      │
│  6. Sign payload                           │
│  7. Zeroize key material                   │
│  8. Return signature / signed tx           │
│                                            │
│  Stored on disk: encrypted wallet files,   │
│  API key files, policies, config           │
└────────────────────────────────────────────┘
```

## Key Lifecycle

```
1. OWS receives a sign request
2. If the credential is an API token, evaluate attached policies before decryption
3. Read the encrypted wallet or API-key-backed secret from disk
4. Derive the decryption key (scrypt for passphrases, HKDF for API tokens)
5. Decrypt key material (mnemonic or private key) into hardened memory
6. Derive the chain-specific signing key if needed
7. Sign the payload
8. Immediately zero out decrypted mnemonic/private key bytes, derived signing key bytes, and KDF-derived key bytes
9. Return only the signature or signed payload
```

Immediate zeroization is critical. In the current Rust implementation this is handled with dedicated secret containers and drop-time zeroization.

## Passphrase Handling

### 1. Interactive prompt (CLI mode)
The CLI can prompt for the passphrase when it is needed.

### 2. Environment variable (CLI mode)
The CLI reads `OWS_PASSPHRASE` and clears it immediately after reading.

### 3. Function parameter (bindings)
The Node and Python bindings accept the credential as a function parameter. That credential may be either the owner's passphrase or an `ows_key_...` API token.

> **Warning:** Environment variables remain the weakest supported delivery mechanism. They are convenient for automation but can leak via process inspection, crash dumps, or child-process inheritance if not cleared promptly.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM misuses a wallet via automation | API tokens scope access and trigger policy checks before decryption |
| Key leaked to logs | OWS does not log key material; audit logging records operations only |
| Core dump contains keys | Process hardening disables core dumps / attach where supported |
| Swap file contains keys | Hardened secret buffers use `mlock()` where available |
| Cold boot / memory forensics | Keys are zeroized immediately after signing; exposure window is short |
| Compromised process memory | Not fully mitigated in the current in-process model; a future subprocess enclave would address this |
| Passphrase brute force | Scrypt slows offline guessing; wallet envelopes use a minimum work factor of `2^16` |

## Key Caching for Batch Performance

Decrypting key material via scrypt adds latency. Implementations SHOULD maintain a short-lived, in-memory cache of derived key material with the following constraints:

| Property | Requirement |
|---|---|
| TTL | No more than 30 seconds; 5 seconds recommended |
| Max entries | Bounded (e.g., 32 entries) with LRU eviction |
| Memory protection | Cached key material MUST be `mlock()`'d and zeroized on eviction |
| Signal handling | Cache MUST be cleared on SIGTERM, SIGINT, and SIGHUP before process exit |
| Cache key | Derived from `SHA-256(mnemonic || passphrase || derivation_path || curve)` — never the raw mnemonic |

## Current Model vs Future Enclave

### Current: in-process hardening + code-path policy enforcement

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► ows-lib (same process)
                ├── token lookup + policy evaluation
                ├── HKDF decrypt wallet secret (mlock'd, zeroized on drop)
                ├── sign
                └── return signature
```

Policy enforcement is handled by the code path — the `ows_key_` credential triggers policy evaluation before decryption. The agent and signer share an address space. In-process hardening (mlock, zeroize, anti-ptrace, anti-coredump) reduces the window for key extraction.

### Future: per-request subprocess enclave

```
Agent → sign_transaction(wallet, chain, tx, "ows_key_...")
          │
          └─► ows-lib (parent process)
                ├── token lookup + policy evaluation
                └── fork/exec ows-enclave
                      ├── receive (token, wallet_id, tx) over stdin
                      ├── HKDF decrypt wallet secret
                      ├── sign
                      ├── zeroize
                      ├── write signature to stdout
                      └── exit
```

The decrypt→sign→wipe path moves to a child process. The parent (agent's process) never has the decrypted secret in its address space. The child is stateless — spawned per request, no daemon, no unlock step. If it crashes, the next request spawns a new one.

## References

- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
