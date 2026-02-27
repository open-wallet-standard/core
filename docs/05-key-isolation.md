# 05 - Key Isolation

> How LWS prevents private keys from leaking to agents, LLMs, logs, or parent processes.

## Design Decision

**LWS mandates that key material is decrypted and used exclusively inside an isolated signing process. The parent process (agent, CLI, app) never has access to plaintext keys. This follows the principle that agents should be able to _use_ wallets without being able to _extract_ keys.**

### Why Process Isolation

The fundamental threat in agent wallet systems is that the agent (or the LLM driving it) could exfiltrate the private key — intentionally via prompt injection, or accidentally via logging/context leakage. We evaluated four isolation strategies:

| Strategy | Security | Performance | Complexity | Used By |
|---|---|---|---|---|
| In-process encryption only | Low — keys in same address space | Fast | Low | Most local keystores |
| TEE enclaves (AWS Nitro, SGX) | Very high — hardware isolation | Fast | High (requires cloud) | Privy, Turnkey, Coinbase |
| MPC/threshold signatures | High — key never reconstituted | Slow (multi-round) | Very high | Lit Protocol |
| **Subprocess isolation** | High — OS-level memory isolation | Fast | Medium | LWS reference impl |

LWS targets local-first deployments where cloud TEEs aren't available. Subprocess isolation provides strong guarantees using standard OS primitives:
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
│  2. Call lws.sign(req)  ───────────►  │  5. Decrypt key (KDF+AES)   │
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
         │    (~/.lws/enclave.sock)                │
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

The enclave needs the vault passphrase to decrypt wallet files. LWS supports three passphrase delivery mechanisms:

### 1. Interactive Prompt (CLI mode)
The enclave prompts for the passphrase on its own TTY. The passphrase never passes through the parent process.

### 2. Environment Variable (daemon mode)
The enclave reads `LWS_PASSPHRASE` from its own environment. The parent process launches the enclave with this variable set. After reading, the enclave SHOULD clear it from its own environment.

### 3. File Descriptor (advanced)
The passphrase is written to a file descriptor inherited by the enclave process. This avoids the passphrase appearing in process environment listings.

## Threat Model

| Threat | Mitigation |
|---|---|
| Agent/LLM exfiltrates key via prompt | Keys never in agent's address space or context |
| Parent process reads child memory | OS enforces process memory isolation (ptrace protections) |
| Key leaked to logs | Enclave has no logging of key material; audit log only records operations |
| Core dump contains keys | Enclave disables core dumps (`prctl(PR_SET_DUMPABLE, 0)` on Linux, `PT_DENY_ATTACH` on macOS) |
| Swap file contains keys | Enclave should `mlock()` key material pages to prevent swapping |
| Cold boot / memory forensics | Keys wiped immediately after signing; window of exposure is milliseconds |
| Compromised enclave binary | Binary integrity can be verified via checksum; future: code signing |
| Passphrase brute force | Scrypt with n=262144 makes brute force computationally expensive |

## Defense in Depth

LWS key isolation is one layer. For maximum security, deployments can add:

1. **OS-level sandboxing**: Run the enclave in a seccomp-bpf sandbox (Linux) or App Sandbox (macOS) restricting syscalls to read/write/crypto operations only.
2. **TEE backends**: Replace the subprocess with a TEE-backed signer (AWS Nitro, Intel SGX) using the same JSON-RPC protocol.
3. **Hardware wallets**: A Ledger/Trezor can serve as the signing backend, with the enclave proxying sign requests to the device.
4. **Key sharding**: Split the encrypted wallet across multiple files requiring quorum access (following Privy's SSS model).

All backends implement the same enclave protocol, making them drop-in replacements.

## Comparison with Industry Approaches

| System | Isolation Mechanism | Local-First? |
|---|---|---|
| Privy | TEE + SSS (2-of-2 or 2-of-3 sharding) | No (cloud) |
| Turnkey | AWS Nitro Enclaves | No (cloud) |
| Coinbase CDP | TEE | No (cloud) |
| Lit Protocol | Distributed key generation across nodes | No (network) |
| Crossmint | Dual-key smart contract + TEE | No (cloud) |
| Phala MCP Wallet | TEE (Intel SGX) on decentralized cloud | No (cloud) |
| **LWS** | **OS process isolation + optional TEE** | **Yes** |

LWS is the only standard designed for local-first operation. The subprocess model works on any machine — no cloud accounts, no network connectivity, no hardware enclaves required. When stronger guarantees are needed, the enclave can be upgraded without changing the interface.

## References

- [Privy: Embedded Wallet Architecture](https://privy.io/blog/embedded-wallet-architecture)
- [Privy: SSS vs MPC-TSS vs TEEs](https://privy.io/blog/embedded-wallet-architecture-breakdown)
- [Turnkey: Key Management in Nitro Enclaves](https://whitepaper.turnkey.com/principles)
- [Phala: TEE-Hosted MCP Wallet Server](https://phala.com/posts/developer-guide-securely-deploy-a-crypto-wallet-mcp-server-on-phala-cloud)
- [Google Cloud: Securing Blockchain-Interacting Agents](https://cloud.google.com/blog/products/identity-security/using-mcp-with-web3-how-to-secure-blockchain-interacting-agents)
- [Linux prctl(2) PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/prctl.2.html)
- [mlock(2) Memory Locking](https://man7.org/linux/man-pages/man2/mlock.2.html)
