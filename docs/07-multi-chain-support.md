# 07 - Multi-Chain Support

> How OWS supports EVM, Solana, Cosmos, Bitcoin, Tron, and future chains through a plugin architecture.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| `ChainSigner` trait (`deriveAddress`, `sign`, `signMessage`, `signTransaction`) | Done | `ows-signer/src/traits.rs` |
| EVM plugin (secp256k1, coin 60, EIP-55 addresses) | Done | `ows-signer/src/chains/evm.rs` |
| Solana plugin (ed25519, coin 501, base58 addresses) | Done | `ows-signer/src/chains/solana.rs` |
| Bitcoin plugin (secp256k1, coin 0, bech32 addresses) | Done | `ows-signer/src/chains/bitcoin.rs` |
| Cosmos plugin (secp256k1, coin 118, bech32 addresses) | Done | `ows-signer/src/chains/cosmos.rs` |
| Tron plugin (secp256k1, coin 195, base58check addresses) | Done | `ows-signer/src/chains/tron.rs` |
| HD derivation: BIP-32 (secp256k1) | Done | `ows-signer/src/hd.rs` |
| HD derivation: SLIP-10 (ed25519) | Done | `ows-signer/src/hd.rs` |
| Default RPC endpoints (11 chains) | Done | `ows-core/src/config.rs` |
| User RPC overrides via config | Done | Merge semantics |
| RPC resolution order (flag > config > default) | Done | CLI + config |
| `ows config show` command | Done | Shows endpoints with (default)/(custom) |
| `buildTransaction()` method on plugins | Not started | Expects pre-built tx bytes |
| `broadcast()` on `ChainSigner` trait | Not started | Broadcasting is in CLI, not trait |
| External plugin discovery (npm `ows-plugin` keyword) | Not started | Chains are hardcoded in `signer_for_chain()` |
| Plugin loading from `~/.ows/config.json` plugins field | Not started | Config field exists but unused |
| Multi-chain account derivation from single mnemonic | Done | `derive_all_accounts()` |

## Design Decision

**OWS uses a chain plugin system where each supported chain provides a signer and transaction builder that implement a standard interface. New chains are added by writing a plugin — no changes to the core spec or implementation are needed.**

This follows x402's scheme/network separation: the core protocol defines _how_ signing works; chain plugins define _what_ gets signed and how transactions are built for a specific network.

### Why Plugins Over Built-In Chains

| Approach | Pros | Cons |
|---|---|---|
| Built-in support for N chains | Simpler initial implementation | Every new chain requires a core release |
| **Plugin architecture** | Permissionless extension; core stays stable | Plugin discovery/loading complexity |
| Chain-agnostic raw signing only | Simplest core | Useless without external tooling to build transactions |

Privy takes the built-in approach (Tier 1/2/3 chain support with different capability levels). Turnkey takes the raw-signing approach (curve primitives only). OWS takes the middle path: a plugin system that ships with first-party plugins for major chains, while allowing anyone to add new chains.

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

  /** Build and serialize a transaction from the OWS transaction object */
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
}
```

## First-Party Plugins

### EVM (`@ows/plugin-evm`)

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

### Solana (`@ows/plugin-solana`)

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

**Commitment mapping:** OWS `confirmations: 1` → Solana `"confirmed"`, `confirmations: 31` → Solana `"finalized"`.

### Cosmos (`@ows/plugin-cosmos`)

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 118 |
| Derivation Path | `m/44'/118'/0'/0/{index}` |
| Address Format | Bech32 (chain-specific prefix) |
| Transaction Library | @cosmjs/stargate |
| RPC Protocol | Tendermint RPC + gRPC |

### Bitcoin (`@ows/plugin-bitcoin`)

| Property | Value |
|---|---|
| Curve | secp256k1 |
| Coin Type | 0 |
| Derivation Path | `m/84'/0'/0'/0/{index}` (native segwit) |
| Address Format | Bech32 (bc1...) |
| Transaction Library | bitcoinjs-lib |
| RPC Protocol | Bitcoin Core JSON-RPC / Electrum |

### Tron (`@ows/plugin-tron`)

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
Shipped with the OWS reference implementation. Loaded automatically based on `chain_type` in wallet files.

### 2. External Plugins
Installed as npm packages with a `ows-plugin` keyword in `package.json`:

```json
{
  "name": "@example/ows-plugin-sui",
  "keywords": ["ows-plugin"],
  "main": "dist/index.js",
  "ows": {
    "chainType": "sui",
    "chains": ["sui:35834a8a"]
  }
}
```

Registered in `~/.ows/config.json`:

```json
{
  "plugins": {
    "sui": "@example/ows-plugin-sui"
  }
}
```

## RPC Configuration

OWS ships with built-in default RPC endpoints for well-known chains, so it works out of the box without any configuration:

| CAIP-2 Chain ID | Default RPC URL |
|---|---|
| `eip155:1` | `https://eth.llamarpc.com` |
| `eip155:137` | `https://polygon-rpc.com` |
| `eip155:42161` | `https://arb1.arbitrum.io/rpc` |
| `eip155:10` | `https://mainnet.optimism.io` |
| `eip155:8453` | `https://mainnet.base.org` |
| `eip155:56` | `https://bsc-dataseed.binance.org` |
| `eip155:43114` | `https://api.avax.network/ext/bc/C/rpc` |
| `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | `https://api.mainnet-beta.solana.com` |
| `bip122:000000000019d6689c085ae165831e93` | `https://mempool.space/api` |
| `cosmos:cosmoshub-4` | `https://cosmos-rest.publicnode.com` |
| `tron:mainnet` | `https://api.trongrid.io` |

These defaults are public, rate-limited endpoints suitable for development and light usage. For production workloads, override them with your own RPC provider in `~/.ows/config.json`:

```json
{
  "rpc": {
    "eip155:1": "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    "eip155:8453": "https://mainnet.base.org",
    "eip155:84532": "https://sepolia.base.org"
  }
}
```

User overrides are merged on top of built-in defaults — you only need to specify the chains you want to change or add. Unlisted defaults remain available.

### RPC Resolution Order

When broadcasting a transaction, the RPC URL is resolved in this order:

1. **`--rpc-url` CLI flag** (or `rpcUrl` parameter in the API) — highest priority
2. **`~/.ows/config.json`** user override for the chain
3. **Built-in default** for well-known chains

### Viewing Configuration

Use `ows config show` to see the active configuration and all RPC endpoints:

```
$ ows config show
Vault:  ~/.ows
Config: ~/.ows/config.json (not found — using defaults)

RPC endpoints:
  bip122:000000000019d6689c085ae165831e93  https://mempool.space/api              (default)
  cosmos:cosmoshub-4                       https://cosmos-rest.publicnode.com      (default)
  eip155:1                                 https://eth.llamarpc.com               (default)
  eip155:10                                https://mainnet.optimism.io             (default)
  ...
```

Endpoints sourced from built-in defaults are annotated `(default)`; user overrides are annotated `(custom)`.

## HD Derivation

OWS uses BIP-39 mnemonics as the root key material, with BIP-32/BIP-44 derivation for all chains:

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
4. Publish as an npm package with `ows-plugin` keyword
5. Document the chain-specific transaction format

No changes to OWS core, the signing interface, or the policy engine are needed.

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
