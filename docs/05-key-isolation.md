# 05 - Key Isolation

> How OWS prevents private keys from leaking to agents, LLMs, logs, or parent processes.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| Core dump disabling (`PR_SET_DUMPABLE` / `PT_DENY_ATTACH`) | Done | `ows-signer/src/process_hardening.rs` |
| `RLIMIT_CORE` set to 0 | Done | `process_hardening.rs` |
| Memory locking (`mlock`) for key material | Done | `ows-signer/src/zeroizing.rs` |
| Zeroization on drop (`SecretBytes`) | Done | `zeroizing.rs` uses `zeroize` crate |
| Signal handlers (SIGTERM/SIGINT/SIGHUP cleanup) | Done | `process_hardening.rs` |
| Key cache with TTL + LRU eviction | Done | `ows-signer/src/key_cache.rs` (5s TTL, 32 entries) |
| Subprocess signing enclave (child process) | Not started | Keys are decrypted in-process, not isolated |
| Unix domain socket / pipe IPC | Not started | No enclave transport |
| JSON-RPC enclave protocol (`sign`, `sign_message`, `unlock`, `lock`, `status`) | Not started | |
| Passphrase delivery: interactive prompt | Partial | CLI prompts directly for wallet create/import/export/sign |
| Passphrase delivery: file descriptor | Not started | |
| Passphrase delivery: env var (`OWS_PASSPHRASE`) with immediate clear | Partial | Passphrase passed as param, not read from env |
| Session-based unlock/lock | Partial | CLI-only passphrase cache via OS keyring |

**Note:** The current implementation provides in-process hardening (mlock, zeroize, anti-debug) but does NOT implement the subprocess isolation model described in the spec. Keys are decrypted within the calling process's address space.

## Design Decision

**OWS mandates that key material is decrypted and used exclusively inside an isolated signing process. The parent process (agent, CLI, app) never has access to plaintext keys. This follows the principle that agents should be able to _use_ wallets without being able to _extract_ keys.**

### Why Process Isolation

The fundamental threat in agent wallet systems is that the agent (or the LLM driving it) could exfiltrate the private key — intentionally via prompt injection, or accidentally via logging/context leakage. We evaluated four isolation strategies:

| Strategy | Security | Performance | Complexity | Used By |
|---|---|---|---|---|
| In-process encryption only | Low — keys in same address space | Fast | Low | Most local keystores |
| TEE enclaves (AWS Nitro, SGX) | Very high — hardware isolation | Fast | High (requires cloud) | Privy, Turnkey, Coinbase |
| MPC/threshold signatures | High — key never reconstituted | Slow (multi-round) | Very high | Lit Protocol |
| **Subprocess isolation** | High — OS-level memory isolation | Fast | Medium | OWS reference impl |

OWS targets local-first deployments where cloud TEEs aren't available. Subprocess isolation provides strong guarantees using standard OS primitives:
- The signing process runs as a separate OS process
- Communication happens over a Unix domain socket or stdin/stdout pipe
- The parent process sends serialized transactions and receives signatures
- Key material exists only in the child process's memory, which is inaccessible to the parent

For deployments where hardware enclaves are available, the signing subprocess can be replaced with a TEE-backed implementation — the interface is identical.

## Architecture

```
┌─────────────────────────────────┐     ┌──────────────────────────────┐
│        Agent / CLI / App        │     │      Signing Enclave         │
│                                 │     │      (child process)         │
│  1. Build transaction           │     │                              │
│  2. Call ows.sign(req)  ───────────►  │  5. Decrypt key (KDF+AES)   │
│                                 │     │  6. Sign transaction         │
│                                 │     │  7. Wipe key from memory     │
│  9. Receive signature  ◄───────────  │  8. Return signature         │
│  10. Broadcast tx               │     │                              │
│                                 │     │  Key material NEVER leaves   │
│  Has: wallet IDs, addresses,    │     │  this process boundary.      │
│  policies, chain configs        │     │                              │
│                                 │     │  Has: encrypted wallet files, │
│  Does NOT have: private keys,   │     │  KDF params, passphrase      │
│  mnemonics, seed phrases        │     │                              │
└─────────────────────────────────┘     └──────────────────────────────┘
         │                                        │
         │    Unix Domain Socket / Pipe           │
         │    (~/.ows/enclave.sock)                │
         └────────────────────────────────────────┘
```

## Enclave Protocol

The signing enclave communicates via a simple JSON-RPC protocol over its transport (Unix socket or stdin/stdout):

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "sign",
  "params": {
    "wallet_id": "3198bc9c-...",
    "chain_id": "eip155:8453",
    "payload": "<hex-encoded-serializable-transaction>",
    "payload_type": "transaction"
  }
}
```

### Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "signature": "0x...",
    "signed_payload": "0x..."
  }
}
```

### Methods

| Method | Description |
|---|---|
| `sign` | Sign a transaction payload |
| `sign_message` | Sign an arbitrary message |
| `unlock` | Provide the vault passphrase to the enclave |
| `lock` | Wipe all decrypted material and require re-authentication |
| `status` | Check if the enclave is unlocked and healthy |

## Key Lifecycle Within the Enclave

```
1. Enclave receives sign request
2. Read encrypted wallet file from disk
3. Derive decryption key from passphrase via KDF (scrypt/PBKDF2)
4. Decrypt key material (mnemonic or private key)
5. Derive chain-specific key via BIP-44 path (if mnemonic)
6. Sign the payload
7. IMMEDIATELY zero out:
   - Decrypted mnemonic/private key bytes
   - Derived chain key bytes
   - KDF-derived decryption key bytes
8. Return only the signature and signed payload
```

Step 7 is critical. Implementations MUST zero key material immediately after signing, not at garbage collection time. In languages with GC (JavaScript, Go), this means using typed arrays (`Uint8Array`) and explicitly filling with zeros. In Rust/C, this means `memset_explicit` or equivalent.

## Passphrase Handling

The enclave needs the vault passphrase to decrypt wallet files. OWS supports three passphrase delivery mechanisms:

### 1. Interactive Prompt (CLI mode)
The enclave prompts for the passphrase on its own TTY. The passphrase never passes through the parent process.

### 2. File Descriptor (recommended for daemon mode)
The passphrase is written to a file descriptor inherited by the enclave process. This is the RECOMMENDED delivery mechanism for non-interactive use because the passphrase never appears in process environment listings or `/proc/[pid]/environ`.

### 3. Environment Variable (fallback for daemon mode)
The enclave reads `OWS_PASSPHRASE` from its own environment. After reading, the enclave MUST immediately clear it from its own environment.

> **Warning:** Environment variables are the least secure delivery mechanism. They are readable in `/proc/[pid]/environ` by any process running as the same user, appear in crash dumps, and are inherited by child processes. Use file descriptor delivery (option 2) when possible. If `OWS_PASSPHRASE` must be used, implementations MUST clear the variable from the process environment immediately after reading it.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM exfiltrates key via prompt | Keys never in agent's address space or context |
| Parent process reads child memory | OS enforces process memory isolation (ptrace protections) |
| Key leaked to logs | Enclave has no logging of key material; audit log only records operations |
| Core dump contains keys | Enclave disables core dumps (`prctl(PR_SET_DUMPABLE, 0)` on Linux, `PT_DENY_ATTACH` on macOS) |
| Swap file contains keys | Enclave MUST `mlock()` key material pages to prevent swapping. Implementations MUST log a warning if `mlock()` fails (e.g., due to `RLIMIT_MEMLOCK` limits). |
| Cold boot / memory forensics | Keys wiped immediately after signing; window of exposure is milliseconds |
| Compromised enclave binary | Binary integrity can be verified via checksum; future: code signing |
| Passphrase brute force | Scrypt with n=262144 makes brute force computationally expensive |

## Defense in Depth

OWS key isolation is one layer. For maximum security, deployments can add:

1. **OS-level sandboxing**: Run the enclave in a seccomp-bpf sandbox (Linux) or App Sandbox (macOS) restricting syscalls to read/write/crypto operations only.
2. **TEE backends**: Replace the subprocess with a TEE-backed signer (AWS Nitro, Intel SGX) using the same JSON-RPC protocol.
3. **Hardware wallets**: A Ledger/Trezor can serve as the signing backend, with the enclave proxying sign requests to the device.
4. **Key sharding**: Split the encrypted wallet across multiple files requiring quorum access (following Privy's SSS model).

All backends implement the same enclave protocol, making them drop-in replacements.

## Key Caching for Batch Performance

Decrypting key material via scrypt (n=262144) takes ~0.5–1s per operation by design. For agents that send batches of transactions, this would create unacceptable latency if the KDF ran per-request.

Implementations SHOULD maintain a short-lived, in-memory cache of derived key material with the following constraints:

| Property | Requirement |
|---|---|
| TTL | No more than 30 seconds; 5 seconds recommended |
| Max entries | Bounded (e.g., 32 entries) with LRU eviction |
| Memory protection | Cached key material MUST be `mlock()`'d and zeroized on eviction |
| Signal handling | Cache MUST be cleared on SIGTERM, SIGINT, and SIGHUP before process exit |
| Cache key | Derived from `SHA-256(mnemonic \|\| passphrase \|\| derivation_path \|\| curve)` — never the raw mnemonic |

The vault `unlock` operation (see [Enclave Protocol](#enclave-protocol)) also establishes a session that avoids repeated passphrase prompts, complementing the key cache for interactive workflows.

## Comparison with Industry Approaches

| System | Isolation Mechanism | Local-First? |
|---|---|---|
| Privy | TEE + SSS (2-of-2 or 2-of-3 sharding) | No (cloud) |
| Turnkey | AWS Nitro Enclaves | No (cloud) |
| Coinbase CDP | TEE | No (cloud) |
| Lit Protocol | Distributed key generation across nodes | No (network) |
| Crossmint | Dual-key smart contract + TEE | No (cloud) |
| Phala Wallet | TEE (Intel SGX) on decentralized cloud | No (cloud) |
| **OWS** | **OS process isolation + optional TEE** | **Yes** |

OWS is the only standard designed for local-first operation. The subprocess model works on any machine — no cloud accounts, no network connectivity, no hardware enclaves required. When stronger guarantees are needed, the enclave can be upgraded without changing the interface.

## References

- [Privy: Embedded Wallet Architecture](https://privy.io/blog/embedded-wallet-architecture)
- [Privy: SSS vs MPC-TSS vs TEEs](https://privy.io/blog/embedded-wallet-architecture-breakdown)
- [Turnkey: Key Management in Nitro Enclaves](https://whitepaper.turnkey.com/principles)
- [Google Cloud: Securing Blockchain-Interacting Agents](https://cloud.google.com/blog/products/identity-security/securing-blockchain-interacting-agents)
- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
