# 03 - Signing Interface

> The core operations exposed by an LWS implementation: signing, sending, simulating, and message signing.

## Design Decision

**LWS defines a minimal, chain-agnostic interface with four core operations (`sign`, `signAndSend`, `signMessage`, `simulate`) that accept serialized chain-specific data and return chain-specific results. The interface never exposes private keys.**

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

LWS takes Turnkey's chain-agnostic signing philosophy, wraps it in Coinbase's provider pattern, and adds simulation as a first-class operation (influenced by Privy's policy engine and ERC-4337's validation model).

## Interface Definition

### `sign(request: SignRequest): Promise<SignResult>`

Signs a transaction without broadcasting it. Returns the signed transaction bytes.

```typescript
interface SignRequest {
  walletId: WalletId;
  chainId: ChainId;                    // CAIP-2
  transaction: SerializedTransaction;  // chain-specific
  simulate?: boolean;                  // default: true
}

interface SignResult {
  signature: string;
  signedTransaction: string;
  simulationResult?: SimulationResult;
}
```

**Flow:**
1. Resolve `walletId` → wallet file
2. Resolve `chainId` → chain plugin
3. If `simulate !== false`, run simulation via chain plugin
4. Evaluate policies against the transaction + simulation result
5. If policies pass, decrypt key material in the signing enclave
6. Sign via chain plugin's signer
7. Wipe key material
8. Return signed transaction

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
- **Cosmos**: ADR-036 off-chain signing

### `simulate(request: SimulateRequest): Promise<SimulationResult>`

Simulates a transaction without signing or broadcasting. Used for pre-flight checks, gas estimation, and policy evaluation.

```typescript
interface SimulateRequest {
  walletId: WalletId;
  chainId: ChainId;
  transaction: SerializedTransaction;
}

interface SimulationResult {
  success: boolean;
  gasEstimate?: string;
  stateChanges?: StateChange[];
  error?: string;
  warnings?: string[];
}
```

Simulation is chain-plugin-dependent:
- **EVM**: `eth_call` + `eth_estimateGas` + trace-based state diff
- **Solana**: `simulateTransaction` RPC
- **Cosmos**: `tx simulate` endpoint

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
interface LwsError {
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
| `SIMULATION_FAILED` | Transaction would revert on-chain |
| `INSUFFICIENT_FUNDS` | Account balance too low |
| `INVALID_PASSPHRASE` | Vault passphrase incorrect |
| `VAULT_LOCKED` | Vault has not been unlocked |
| `BROADCAST_FAILED` | Transaction broadcast rejected by RPC node |
| `TIMEOUT` | Confirmation wait exceeded |

## Concurrency

LWS implementations MUST support concurrent signing requests across different wallets. Concurrent requests to the same wallet MUST be serialized to prevent nonce conflicts on chains that require sequential nonces (EVM, Cosmos). Implementations SHOULD use a per-wallet mutex or nonce manager.

## References

- [Coinbase AgentKit: ActionProviders](https://github.com/coinbase/agentkit)
- [Privy Server Wallet API](https://docs.privy.io/guide/server-wallets/usage/ethereum)
- [Solana Wallet Standard: Features](https://github.com/anza-xyz/wallet-standard)
- [Turnkey Signing API](https://docs.turnkey.com)
- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-712: Typed Structured Data](https://eips.ethereum.org/EIPS/eip-712)
- [ERC-4337: UserOperation Validation](https://eips.ethereum.org/EIPS/eip-4337)
