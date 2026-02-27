# 07 - Multi-Chain Support

> How LWS supports EVM, Solana, Cosmos, Bitcoin, Tron, and future chains through a plugin architecture.

## Design Decision

**LWS uses a chain plugin system where each supported chain provides a signer, transaction builder, and simulator that implement a standard interface. New chains are added by writing a plugin — no changes to the core spec or implementation are needed.**

This follows x402's scheme/network separation: the core protocol defines _how_ signing works; chain plugins define _what_ gets signed and how transactions are built for a specific network.

### Why Plugins Over Built-In Chains

| Approach | Pros | Cons |
|---|---|---|
| Built-in support for N chains | Simpler initial implementation | Every new chain requires a core release |
| **Plugin architecture** | Permissionless extension; core stays stable | Plugin discovery/loading complexity |
| Chain-agnostic raw signing only | Simplest core | Useless without external tooling to build transactions |

Privy takes the built-in approach (Tier 1/2/3 chain support with different capability levels). Turnkey takes the raw-signing approach (curve primitives only). LWS takes the middle path: a plugin system that ships with first-party plugins for major chains, while allowing anyone to add new chains.

## Plugin Interface

Each chain plugin implements the `ChainPlugin` interface:

```typescript
interface ChainPlugin {
  /** Chain type identifier */
  chainType: string;                    // "evm", "solana", "cosmos", etc.

  /** Supported CAIP-2 chain IDs */
  supportedChains: ChainId[];

  /** Cryptographic curve used for key derivation */
  curve: "secp256k1" | "ed25519";

  /** BIP-44 coin type for HD derivation */
  coinType: number;                     // 60 for ETH, 501 for SOL, etc.

  /** Derive a chain-specific address from a private key */
  deriveAddress(privateKey: Uint8Array): string;

  /** Build and serialize a transaction from the LWS transaction object */
  buildTransaction(
    tx: SerializedTransaction,
    chainId: ChainId,
    address: string,
    rpcUrl: string
  ): Promise<Uint8Array>;

  /** Sign a serialized transaction */
  sign(
    serializedTx: Uint8Array,
    privateKey: Uint8Array
  ): Promise<{ signature: Uint8Array; signedTx: Uint8Array }>;

  /** Sign an arbitrary message */
  signMessage(
    message: Uint8Array,
    privateKey: Uint8Array,
    options?: { typed?: boolean }      // EIP-712 for EVM
  ): Promise<Uint8Array>;

  /** Broadcast a signed transaction */
  broadcast(
    signedTx: Uint8Array,
    chainId: ChainId,
    rpcUrl: string
  ): Promise<{ hash: string }>;

  /** Simulate a transaction */
  simulate(
    tx: SerializedTransaction,
    chainId: ChainId,
    address: string,
    rpcUrl: string
  ): Promise<SimulationResult>;

  /** Get account balance */
  getBalance(
    address: string,
    chainId: ChainId,
    rpcUrl: string,
    tokens?: string[]
  ): Promise<BalanceResult>;
}

interface BalanceResult {
  native: string;                       // in smallest unit
  tokens: Array<{
    address: string;
    symbol?: string;
    balance: string;
    decimals: number;
  }>;
}
```

## First-Party Plugins

### EVM (`@lws/plugin-evm`)

Supports all EVM-compatible chains: Ethereum, Base, Polygon, Arbitrum, Optimism, Avalanche, BSC, etc.

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 60 |
| Derivation Path | `m/44'/60'/0'/0/{index}` |
| Address Format | `0x` + keccak256(pubkey)[12:] (EIP-55 checksum) |
| Transaction Library | ethers.js / viem |
| RPC Protocol | JSON-RPC (eth_*) |

**Transaction format:**
```typescript
{
  to: "0x...",
  value: "0x...",              // wei, hex
  data: "0x...",               // calldata
  gasLimit: "0x...",           // auto-estimated if omitted
  maxFeePerGas: "0x...",       // EIP-1559
  maxPriorityFeePerGas: "0x...",
  nonce: 0,                   // auto-fetched if omitted
  type: 2                     // EIP-1559 by default
}
```

**Simulation:** `eth_call` + `eth_estimateGas` + optional `debug_traceCall` for state diffs.

### Solana (`@lws/plugin-solana`)

| Property | Value |
|---|---|
| Curve | ed25519 |
| Coin Type | 501 |
| Derivation Path | `m/44'/501'/{index}'/0'` |
| Address Format | Base58-encoded ed25519 public key |
| Transaction Library | @solana/web3.js |
| RPC Protocol | JSON-RPC (Solana-specific) |

**Transaction format:**
```typescript
{
  instructions: [
    {
      programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      keys: [
        { pubkey: "...", isSigner: true, isWritable: true },
        { pubkey: "...", isSigner: false, isWritable: true }
      ],
      data: "..."               // base64
    }
  ],
  recentBlockhash: "...",       // auto-fetched if omitted
  feePayer: "..."               // defaults to wallet address
}
```

**Simulation:** `simulateTransaction` RPC method.

**Commitment mapping:** LWS `confirmations: 1` → Solana `"confirmed"`, `confirmations: 31` → Solana `"finalized"`.

### Cosmos (`@lws/plugin-cosmos`)

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 118 |
| Derivation Path | `m/44'/118'/0'/0/{index}` |
| Address Format | Bech32 (chain-specific prefix) |
| Transaction Library | @cosmjs/stargate |
| RPC Protocol | Tendermint RPC + gRPC |

### Bitcoin (`@lws/plugin-bitcoin`)

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 0 |
| Derivation Path | `m/84'/0'/0'/0/{index}` (native segwit) |
| Address Format | Bech32 (bc1...) |
| Transaction Library | bitcoinjs-lib |
| RPC Protocol | Bitcoin Core JSON-RPC / Electrum |

### Tron (`@lws/plugin-tron`)

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 195 |
| Derivation Path | `m/44'/195'/0'/0/{index}` |
| Address Format | Base58Check (T...) |
| Transaction Library | tronweb |
| RPC Protocol | Tron HTTP API |

## Plugin Discovery and Loading

Plugins are discovered in two ways:

### 1. Built-In Plugins
Shipped with the LWS reference implementation. Loaded automatically based on `chain_type` in wallet files.

### 2. External Plugins
Installed as npm packages with a `lws-plugin` keyword in `package.json`:

```json
{
  "name": "@example/lws-plugin-sui",
  "keywords": ["lws-plugin"],
  "main": "dist/index.js",
  "lws": {
    "chainType": "sui",
    "chains": ["sui:35834a8a"]
  }
}
```

Registered in `~/.lws/config.json`:

```json
{
  "plugins": {
    "sui": "@example/lws-plugin-sui"
  }
}
```

## RPC Configuration

Each chain needs an RPC endpoint. Defaults are configured per chain in `~/.lws/config.json`:

```json
{
  "rpc": {
    "eip155:1": "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    "eip155:8453": "https://mainnet.base.org",
    "eip155:84532": "https://sepolia.base.org",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "https://api.mainnet-beta.solana.com"
  }
}
```

RPC URLs can also be overridden per-request via the `rpcUrl` parameter in signing requests.

## HD Derivation

LWS uses BIP-39 mnemonics as the root key material, with BIP-32/BIP-44 derivation for all chains:

```
Mnemonic (BIP-39)
    │
    ▼
Master Seed (512 bits via PBKDF2)
    │
    ├── m/44'/60'/0'/0/0  → EVM Account 0
    ├── m/44'/60'/0'/0/1  → EVM Account 1
    ├── m/44'/501'/0'/0'  → Solana Account 0
    ├── m/44'/118'/0'/0/0 → Cosmos Account 0
    ├── m/84'/0'/0'/0/0   → Bitcoin Account 0 (native segwit)
    └── m/44'/195'/0'/0/0 → Tron Account 0
```

A single mnemonic can derive accounts across all supported chains. The wallet file stores the encrypted mnemonic; chain plugins derive the appropriate private key from it using their coin type and derivation path.

## Adding a New Chain

To add support for a new chain:

1. Implement the `ChainPlugin` interface
2. Register a CAIP-2 namespace (if not already registered at [chainagnostic.org](https://chainagnostic.org))
3. Specify the BIP-44 coin type (from [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md))
4. Publish as an npm package with `lws-plugin` keyword
5. Document the chain-specific transaction format and simulation behavior

No changes to LWS core, the signing interface, or the policy engine are needed.

## References

- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-44: Registered Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
- [CAIP-2: Blockchain ID](https://chainagnostic.org/CAIPs/caip-2)
- [Privy: Chain Support Tiers](https://docs.privy.io/wallets/overview/chains)
- [Privy: HD Wallets](https://docs.privy.io/recipes/hd-wallets)
- [x402: Scheme/Network Separation](https://github.com/coinbase/x402/tree/main/specs)
- [Turnkey: Curve-Primitive Signing](https://docs.turnkey.com)
