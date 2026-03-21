# 07 - Supported Chains

> Canonical reference for all chains supported by OWS: identifiers, derivation paths, address formats, RPC endpoints, and asset identification.

## Implementation Status

| Feature | Status | Notes |
|---------|--------|-------|
| CAIP-2 chain ID parsing (`namespace:reference`) | Done | `ows-core/src/caip.rs` |
| CAIP-10 account IDs (`chain_id:address`) | Done | Stored in wallet `account_id` field |
| Registered chain families (9 families, 15 networks) | Done | `ows-core/src/chain.rs` |
| Per-chain signers (EVM, Solana, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin) | Done | `ows-signer/src/chains/` |
| HD derivation: BIP-32 (secp256k1) + SLIP-10 (ed25519) | Done | `ows-signer/src/hd.rs` |
| Default RPC endpoints | Done | `ows-core/src/config.rs` |
| User RPC overrides via config | Done | Merge semantics |
| Shorthand aliases (e.g. `ethereum` → `eip155:1`) | Done | `parse_chain()` in CLI |
| Asset identification (`chain_id:contract` / `native`) | Not started | No asset ID scheme |

## Identifier Types

OWS uses [CAIP](https://chainagnostic.org/) identifiers throughout. All wallet files, policy contexts, audit logs, and API parameters use these canonical formats — never shorthand aliases.

```typescript
/** CAIP-2 chain identifier: namespace:reference */
type ChainId = `${string}:${string}`;
// e.g. "eip155:8453", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

/** CAIP-10 account identifier: chain_id:address */
type AccountId = `${ChainId}:${string}`;
// e.g. "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"

/** Asset identifier: chain_id:contract_address or chain_id:native */
type AssetId = `${ChainId}:${string}`;
// e.g. "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" (USDC on Base)
// e.g. "eip155:8453:native" (ETH on Base)
```

The `native` token refers to the chain's native currency (ETH, SOL, SUI, BTC, ATOM, TRX, TON, etc.).

## Chain Families

OWS groups chains into families that share a cryptographic curve and address derivation scheme. A single mnemonic derives accounts for all families.

| Family | Curve | Coin Type | Derivation Path | Address Format | CAIP-2 Namespace |
|---|---|---|---|---|---|
| EVM | secp256k1 | 60 | `m/44'/60'/0'/0/{index}` | EIP-55 checksummed hex (`0x...`) | `eip155` |
| Solana | ed25519 | 501 | `m/44'/501'/{index}'/0'` | Base58-encoded public key | `solana` |
| Bitcoin | secp256k1 | 0 | `m/84'/0'/0'/0/{index}` | Bech32 native segwit (`bc1...`) | `bip122` |
| Cosmos | secp256k1 | 118 | `m/44'/118'/0'/0/{index}` | Bech32 (`cosmos1...`) | `cosmos` |
| Tron | secp256k1 | 195 | `m/44'/195'/0'/0/{index}` | Base58Check (`T...`) | `tron` |
| TON | ed25519 | 607 | `m/44'/607'/{index}'` | Base64url wallet v5r1 (`UQ...`) | `ton` |
| Sui | ed25519 | 784 | `m/44'/784'/{index}'/0'/0'` | `0x` + BLAKE2b-256 hex (32 bytes) | `sui` |
| Spark | secp256k1 | 8797555 | `m/84'/0'/0'/0/{index}` | `spark:` + compressed pubkey hex | `spark` |
| Filecoin | secp256k1 | 461 | `m/44'/461'/0'/0/{index}` | `f1` + base32(blake2b-160) | `fil` |

## Known Networks

Each network has a CAIP-2 chain ID and a default public RPC endpoint.

### EVM Networks

| Name | CAIP-2 Chain ID | Default RPC URL |
|---|---|---|
| Ethereum | `eip155:1` | `https://eth.llamarpc.com` |
| Polygon | `eip155:137` | `https://polygon-rpc.com` |
| Arbitrum | `eip155:42161` | `https://arb1.arbitrum.io/rpc` |
| Optimism | `eip155:10` | `https://mainnet.optimism.io` |
| Base | `eip155:8453` | `https://mainnet.base.org` |
| BSC | `eip155:56` | `https://bsc-dataseed.binance.org` |
| Avalanche | `eip155:43114` | `https://api.avax.network/ext/bc/C/rpc` |

### Non-EVM Networks

| Name | CAIP-2 Chain ID | Default RPC URL |
|---|---|---|
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | `https://api.mainnet-beta.solana.com` |
| Bitcoin | `bip122:000000000019d6689c085ae165831e93` | `https://mempool.space/api` |
| Cosmos | `cosmos:cosmoshub-4` | `https://cosmos-rest.publicnode.com` |
| Tron | `tron:mainnet` | `https://api.trongrid.io` |
| TON | `ton:mainnet` | `https://toncenter.com/api/v2` |
| Sui | `sui:mainnet` | `https://fullnode.mainnet.sui.io:443` |
| Spark | `spark:mainnet` | — |
| Filecoin | `fil:mainnet` | `https://api.node.glif.io/rpc/v1` |

Default endpoints are public, rate-limited, and suitable for development.

## RPC Configuration

Override default endpoints in `~/.ows/config.json`:

```json
{
  "rpc": {
    "eip155:1": "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    "eip155:8453": "https://mainnet.base.org",
    "eip155:84532": "https://sepolia.base.org"
  }
}
```

User overrides are merged on top of built-in defaults — you only need to specify chains you want to change or add.

**Resolution order** when broadcasting:

1. `--rpc-url` CLI flag (or `rpcUrl` API parameter) — highest priority
2. `~/.ows/config.json` user override
3. Built-in default

## Shorthand Aliases

Implementations MAY support shorthand aliases in CLI contexts:

```
ethereum  → eip155:1
base      → eip155:8453
polygon   → eip155:137
arbitrum  → eip155:42161
optimism  → eip155:10
bsc       → eip155:56
avalanche → eip155:43114
solana    → solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
bitcoin   → bip122:000000000019d6689c085ae165831e93
cosmos    → cosmos:cosmoshub-4
tron      → tron:mainnet
ton       → ton:mainnet
sui       → sui:mainnet
spark     → spark:mainnet
filecoin  → fil:mainnet
```

Aliases MUST be resolved to full CAIP-2 identifiers before any processing. They MUST NOT appear in wallet files, policy files, or audit logs.

## HD Derivation

OWS uses BIP-39 mnemonics as the root key material, with BIP-32/BIP-44 derivation for all chains:

```
Mnemonic (BIP-39)
    │
    ▼
Master Seed (512 bits via PBKDF2)
    │
    ├── m/44'/60'/0'/0/0    → EVM Account 0
    ├── m/44'/501'/0'/0'    → Solana Account 0
    ├── m/84'/0'/0'/0/0     → Bitcoin Account 0 (native segwit)
    ├── m/44'/118'/0'/0/0   → Cosmos Account 0
    ├── m/44'/195'/0'/0/0   → Tron Account 0
    ├── m/44'/607'/0'       → TON Account 0
    ├── m/44'/784'/0'/0'/0' → Sui Account 0
    ├── m/84'/0'/0'/0/0     → Spark Account 0
    └── m/44'/461'/0'/0/0   → Filecoin Account 0
```

A single mnemonic derives accounts across all supported chains. The wallet file stores the encrypted mnemonic; the signer derives the appropriate private key using each chain's coin type and derivation path.

## Adding a New Chain

1. Implement the `ChainSigner` trait (`deriveAddress`, `sign`, `signMessage`)
2. Register a CAIP-2 namespace (if not already registered at [chainagnostic.org](https://chainagnostic.org))
3. Specify the BIP-44 coin type (from [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md))
4. Add a default RPC endpoint to `Config::default_rpc()`
5. Add the chain to the `KNOWN_CHAINS` registry

No changes to OWS core, the signing interface, or the policy engine are needed.

## References

- [CAIP-2: Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10: Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic Code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-44: Registered Coin Types](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)
