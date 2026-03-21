# 02 - Signing Interface

> The core operations exposed by an OWS implementation: signing, sending, and message signing.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| `sign` (sign transaction) | Done | CLI `ows sign tx`, `ows-signer` trait |
| `signAndSend` (sign + broadcast) | Done | CLI `ows sign send-tx`, per-chain broadcast |
| `signMessage` (arbitrary message signing) | Done | CLI `ows sign message`, EIP-712 supported |
| `signTypedData` (EIP-712 typed structured data) | Done | SDK-level API, CLI `--typed-data` flag |
| EVM broadcast (`eth_sendRawTransaction`) | Done | `send_transaction.rs` |
| Solana broadcast (`sendTransaction`) | Done | `send_transaction.rs` |
| Sui broadcast (`sui_executeTransactionBlock`) | Done | `ops.rs` |
| Bitcoin broadcast (mempool.space REST) | Done | `send_transaction.rs` |
| Cosmos broadcast (`/cosmos/tx/v1beta1/txs`) | Done | `send_transaction.rs` |
| Tron broadcast (`/wallet/broadcasthex`) | Done | `send_transaction.rs` |
| Error code: `WALLET_NOT_FOUND` | Done | `ows-core/src/error.rs` |
| Error code: `CHAIN_NOT_SUPPORTED` | Done | `ows-core/src/error.rs` |
| Error code: `INVALID_PASSPHRASE` | Done | `ows-core/src/error.rs` |
| Error code: `POLICY_DENIED` | Not started | No policy engine |
| Error code: `INSUFFICIENT_FUNDS` | Not started | |
| Error code: `VAULT_LOCKED` | Not started | No session/lock concept |
| Error code: `BROADCAST_FAILED` | Not started | |
| Error code: `TIMEOUT` | Not started | |
| Concurrency (per-wallet mutex / nonce manager) | Not started | No concurrency controls |
| Caller authentication (owner vs agent) | Not started | No two-tier access model |

## Design Decision

**OWS defines a minimal, chain-agnostic interface with three core operations (`sign`, `signAndSend`, `signMessage`) that accept serialized chain-specific data and return chain-specific results. The interface never exposes private keys.**

### Why This Shape

We studied the interfaces of six major wallet systems:

| System | Interface Style | Key Insight |
|---|---|---|
| Privy | REST + SDK (chain-specific methods) | Separate `ethereum.sendTransaction` vs `solana.signTransaction` |
| Coinbase AgentKit | ActionProviders + WalletProviders | Provider pattern cleanly separates "what" from "how" |
| Solana Wallet Standard | Feature-based registration | `signTransaction`, `signMessage` as opt-in features |
| W3C Universal Wallet | `lock/unlock/add/remove/export` | Lifecycle operations, not signing |
| WalletConnect v2 | JSON-RPC over relay | `wallet_invokeMethod` routes to chain-specific RPC |
| Turnkey | REST API (sign arbitrary payloads) | Curve-primitive signing, chain-agnostic |

OWS takes Turnkey's chain-agnostic signing philosophy and wraps it in Coinbase's provider pattern.

## Interface Definition

### `sign(request: SignRequest): Promise<SignResult>`

Signs a transaction without broadcasting it. Returns the signed transaction bytes.

```typescript
interface SignRequest {
  walletId: WalletId;
  chainId: ChainId;                    // CAIP-2
  transaction: SerializedTransaction;  // chain-specific
}

interface SignResult {
  signature: string;
  signedTransaction: string;
}
```

**Flow:**
1. Resolve `walletId` → wallet file
2. Resolve `chainId` → chain plugin
3. Authenticate caller: owner (passphrase/passkey) or agent (API key)
4. If agent: verify wallet is in API key's `walletIds` scope; evaluate API key's policies against the transaction
5. If owner: skip policy evaluation (sudo access)
6. If policies pass (or owner), decrypt key material in the signing enclave
7. Sign via chain plugin's signer
8. Wipe key material
9. Return signed transaction

### `signAndSend(request: SignAndSendRequest): Promise<SignAndSendResult>`

Signs and broadcasts a transaction, optionally waiting for confirmation.

```typescript
interface SignAndSendRequest extends SignRequest {
  maxRetries?: number;                 // broadcast retries (default: 3)
  confirmations?: number;             // blocks to wait (default: 1)
}

interface SignAndSendResult extends SignResult {
  transactionHash: string;
  blockNumber?: number;
  status: "confirmed" | "pending" | "failed";
}
```

The chain plugin handles broadcasting via its configured RPC endpoint. The `confirmations` parameter is chain-specific: on EVM chains it means block confirmations; on Solana it maps to commitment levels (`confirmed` = 1, `finalized` ≈ 31).

#### CLI: `ows sign send-tx`

The `ows sign send-tx` command provides sign-and-broadcast from the command line:

```bash
ows sign send-tx \
  --chain evm \
  --wallet agent-treasury \
  --tx 0x<hex-encoded-unsigned-tx> \
  --index 0 \
  --rpc-url https://eth-sepolia.g.alchemy.com/v2/demo   # optional override
```

The command signs the transaction using the wallet's encrypted mnemonic, resolves the RPC endpoint (flag > config override > built-in default), broadcasts via the chain-appropriate protocol, and prints the transaction hash. Use `--json` for structured output including `tx_hash`, `chain`, `rpc_url`, and `signature`.

Per-chain broadcast protocols:

| Chain | Broadcast Method |
|---|---|
| EVM | JSON-RPC `eth_sendRawTransaction` |
| Solana | JSON-RPC `sendTransaction` (base64-encoded) |
| Bitcoin | POST raw hex to `{rpc}/tx` (mempool.space REST) |
| Cosmos | POST to `{rpc}/cosmos/tx/v1beta1/txs` (base64 tx_bytes) |
| Tron | POST to `{rpc}/wallet/broadcasthex` |
| Sui | JSON-RPC `sui_executeTransactionBlock` (base64 tx + sig) |

### `signMessage(request: SignMessageRequest): Promise<SignMessageResult>`

Signs an arbitrary message (for authentication, attestation, or off-chain signatures like EIP-712).

```typescript
interface SignMessageRequest {
  walletId: WalletId;
  chainId: ChainId;
  message: string | Uint8Array;
  encoding?: "utf8" | "hex";
  typedData?: TypedData;               // EIP-712 typed data (EVM only)
}

interface SignMessageResult {
  signature: string;
  recoveryId?: number;                 // for secp256k1 recovery
}
```

Message signing follows chain-specific conventions:
- **EVM**: `personal_sign` (EIP-191) or `eth_signTypedData_v4` (EIP-712)
- **Solana**: Ed25519 signature over the raw message bytes
- **Sui**: Intent-prefixed (scope=3) BLAKE2b-256 digest, Ed25519 signature
- **Cosmos**: ADR-036 off-chain signing
- **Filecoin**: Blake2b-256 hash then secp256k1 signing

### `signTypedData(request: SignTypedDataRequest): Promise<SignMessageResult>`

Signs EIP-712 typed structured data. This is a dedicated operation separate from `signMessage` to provide a clean SDK interface for typed data signing without overloading the message signing API.

```typescript
interface SignTypedDataRequest {
  walletId: WalletId;
  chainId: ChainId;                    // Must be an EVM chain
  typedDataJson: string;               // JSON string of EIP-712 typed data
}
```

The `typedDataJson` field must be a JSON string containing the standard EIP-712 fields: `types`, `primaryType`, `domain`, and `message`.

```json
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "chainId", "type": "uint256"}
    ],
    "Transfer": [
      {"name": "to", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ]
  },
  "primaryType": "Transfer",
  "domain": {"name": "MyDApp", "chainId": "1"},
  "message": {"to": "0xabc...", "amount": "1000"}
}
```

Returns a `SignMessageResult` with the signature and recovery ID. Only supported for EVM chains — calling with a non-EVM chain returns a `CHAIN_NOT_SUPPORTED` error.

## SerializedTransaction Format

The `SerializedTransaction` type is a union discriminated by chain type. Each chain plugin defines its own transaction shape:

```typescript
// EVM
interface EvmTransaction {
  to: string;
  value?: string;             // wei (hex or decimal)
  data?: string;              // calldata (hex)
  gasLimit?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  nonce?: number;             // auto-filled if omitted
  chainId?: number;           // auto-filled from CAIP-2
}

// Solana
interface SolanaTransaction {
  instructions: SolanaInstruction[];
  recentBlockhash?: string;   // auto-filled if omitted
  feePayer?: string;           // defaults to wallet address
}

interface SolanaInstruction {
  programId: string;
  keys: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>;
  data: string;               // base64
}

// Cosmos
interface CosmosTransaction {
  messages: CosmosMessage[];
  fee?: { amount: CosmosCoin[]; gas: string };
  memo?: string;
}
```

Chain plugins are responsible for filling in defaults (nonce, gas, blockhash) and serializing to the chain's wire format.

## Error Handling

All operations return structured errors:

```typescript
interface OwsError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}
```

### Error Codes

| Code | Meaning |
|---|---|
| `WALLET_NOT_FOUND` | No wallet with the given ID exists |
| `CHAIN_NOT_SUPPORTED` | No plugin loaded for the given chain |
| `POLICY_DENIED` | Transaction rejected by policy engine |
| `INSUFFICIENT_FUNDS` | Account balance too low |
| `INVALID_PASSPHRASE` | Vault passphrase incorrect |
| `VAULT_LOCKED` | Vault has not been unlocked |
| `BROADCAST_FAILED` | Transaction broadcast rejected by RPC node |
| `TIMEOUT` | Confirmation wait exceeded |

## Concurrency

OWS implementations MUST support concurrent signing requests across different wallets. Concurrent requests to the same wallet MUST be serialized to prevent nonce conflicts on chains that require sequential nonces (EVM, Cosmos). Implementations SHOULD use a per-wallet mutex or nonce manager.

## References

- [Coinbase AgentKit: ActionProviders](https://github.com/coinbase/agentkit)
- [Privy Server Wallet API](https://docs.privy.io/guide/server-wallets/usage/ethereum)
- [Solana Wallet Standard: Features](https://github.com/anza-xyz/wallet-standard)
- [Turnkey Signing API](https://docs.turnkey.com)
- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-712: Typed Structured Data](https://eips.ethereum.org/EIPS/eip-712)
