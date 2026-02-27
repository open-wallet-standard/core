# 02 - Chain-Agnostic Addressing

> How LWS identifies chains, accounts, and assets without being locked to any single ecosystem.

## Design Decision

**LWS uses CAIP (Chain Agnostic Improvement Proposals) identifiers as the canonical addressing scheme for all chains, accounts, and method invocations.**

### Why CAIP

We evaluated three approaches to multi-chain identification:

| Approach | Example | Pros | Cons |
|---|---|---|---|
| Chain-specific enums | `"ethereum"`, `"solana"` | Simple | Ambiguous (mainnet vs testnet?); non-extensible |
| Numeric chain IDs | `8453` | EVM-native | Only works for EVM; conflicts across ecosystems |
| **CAIP-2 / CAIP-10** | `eip155:8453` | Universal, unambiguous, extensible, industry standard | Slightly verbose |

CAIP identifiers are already adopted by x402, Privy, WalletConnect v2, and the Chain Agnostic Standards Alliance. They are the only addressing scheme that works across EVM, Solana, Cosmos, Bitcoin, Tron, and future chains without ambiguity.

## CAIP-2: Chain Identification

Format: `namespace:reference`

The namespace identifies the chain ecosystem. The reference identifies the specific network within that ecosystem.

### Registered Namespaces

| Namespace | Ecosystem | Reference Format | Example |
|---|---|---|---|
| `eip155` | EVM (Ethereum, Base, Polygon, etc.) | Decimal chain ID | `eip155:1` (Ethereum mainnet), `eip155:8453` (Base) |
| `solana` | Solana | Genesis hash (first 32 bytes) | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| `cosmos` | Cosmos | Chain ID string | `cosmos:cosmoshub-4` |
| `bip122` | Bitcoin | Genesis block hash (first 32 bytes) | `bip122:000000000019d6689c085ae165831e93` |
| `tron` | Tron | Genesis block hash | `tron:00000000000000001ebf88508a03865c` |
| `polkadot` | Polkadot | Genesis hash (first 32 bytes) | `polkadot:91b171bb158e2d3848fa23a9f1c25182` |

New chains are added by registering a CAIP-2 namespace — no changes to the LWS core spec are needed.

## CAIP-10: Account Identification

Format: `chain_id:account_address`

Combines a CAIP-2 chain ID with the chain-native account address.

```
eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb
solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7S3P4HxJpyyigGzodYwHtCxZyUQe9JiBMHyLWXo5Dyoy
cosmos:cosmoshub-4:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0
```

Every account in an LWS wallet is identified by its CAIP-10 ID. This enables:
- Unambiguous cross-chain references
- Deterministic account lookup across tools
- Standard format for audit logs and policy rules

## CAIP-27: Method Invocation

LWS adopts CAIP-27 semantics for RPC method routing. When a signing request arrives, it is scoped to a specific chain:

```json
{
  "method": "lws_signTransaction",
  "params": {
    "chainId": "eip155:8453",
    "walletId": "3198bc9c-...",
    "request": {
      "method": "eth_sendTransaction",
      "params": [{ "to": "0x...", "value": "0x..." }]
    }
  }
}
```

The `chainId` field determines which chain plugin handles the request. The inner `request` object contains chain-native RPC parameters.

## Asset Identification

Assets (tokens) are identified by their chain ID plus contract address:

```
eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913   # USDC on Base
eip155:8453:native                                         # ETH on Base
solana:5eykt...:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v  # USDC on Solana
```

The special token `native` refers to the chain's native currency (ETH, SOL, TRX, etc.).

## How This Affects the Interface

All LWS interface methods accept CAIP identifiers:

```typescript
// Sign a transaction on Base
await lws.sign({
  walletId: "3198bc9c-...",
  chainId: "eip155:8453",          // CAIP-2
  transaction: { /* ... */ }
});

// List accounts (returns CAIP-10 identifiers)
const accounts = await lws.listAccounts("3198bc9c-...");
// => ["eip155:8453:0xab16...", "eip155:1:0xab16..."]

// Policy rule scoped to a chain
const rule: PolicyRule = {
  type: "max_value",
  chainId: "eip155:8453",          // CAIP-2
  asset: "native",
  maxAmount: "1000000000000000000", // 1 ETH in wei
  period: "daily"
};
```

## Shorthand Aliases (Optional)

Implementations MAY support shorthand aliases in CLI contexts for convenience:

```
base      → eip155:8453
ethereum  → eip155:1
solana    → solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
bitcoin   → bip122:000000000019d6689c085ae165831e93
```

Aliases MUST be resolved to full CAIP-2 identifiers before any processing. They MUST NOT appear in wallet files, policy files, or audit logs.

## References

- [CAIP-2: Blockchain ID Specification](https://chainagnostic.org/CAIPs/caip-2)
- [CAIP-10: Account ID Specification](https://chainagnostic.org/CAIPs/caip-10)
- [CAIP-25: Wallet Session Authorization](https://chainagnostic.org/CAIPs/caip-25)
- [CAIP-27: Wallet Invoke Method](https://chainagnostic.org/CAIPs/caip-27)
- [CAIP-217: Authorization Scopes](https://chainagnostic.org/CAIPs/caip-217)
- [x402 Network Identifiers](https://github.com/coinbase/x402)
- [Privy CAIP-2 Usage](https://docs.privy.io/wallets/overview/chains)
- [WalletConnect Multi-Chain Sessions](https://specs.walletconnect.com/2.0)
