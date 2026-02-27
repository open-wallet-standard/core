# Local Wallet Standard (LWS) v0.1

> An open standard for secure local wallet storage and agent access.

## Abstract

The Local Wallet Standard (LWS) defines how cryptographic wallets are stored on a local filesystem, how agents and CLI tools access them through a unified interface, and how policy-based controls govern what operations are permitted — all without ever exposing private keys to the calling process.

As AI agents become first-class participants in blockchain ecosystems — executing trades, paying for services, managing treasuries — they need a standardized, secure way to access wallets locally. Today, every tool rolls its own approach: environment variables with raw private keys, proprietary cloud APIs, bespoke keystore formats. LWS replaces this fragmentation with a single open standard, analogous to what [x402](https://x402.org) did for machine-to-machine payments.

## Design Principles

1. **Keys never leave the vault.** Private keys are encrypted at rest and decrypted only inside an isolated signing process. They are never exposed to agent prompts, LLM contexts, or parent processes.

2. **Chain-agnostic by default.** The standard uses [CAIP-2](https://chainagnostic.org/CAIPs/caip-2) chain identifiers and [CAIP-10](https://chainagnostic.org/CAIPs/caip-10) account identifiers. EVM, Solana, Tron, Cosmos, Bitcoin, and any future chain are first-class citizens.

3. **Policy before signing.** Every transaction passes through a policy engine before key material is touched. Policies can enforce spending limits, allowlisted contracts, chain restrictions, and simulation requirements.

4. **One interface, any consumer.** CLI tools, MCP servers, REST APIs, and direct library calls all use the same abstract interface. A wallet created by one tool is usable by any other.

5. **Open and forkable.** The standard is permissionlessly extensible. New chains, policy types, and storage backends are added via plugins, not core spec changes — following the scheme/network/transport separation pioneered by x402.

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Agent / CLI / App                  │
│              (Claude, dawn-cli, custom)              │
└──────────────────────┬──────────────────────────────┘
                       │ LWS Interface (RPC / Library)
                       ▼
┌─────────────────────────────────────────────────────┐
│                  Access Layer                        │
│         MCP Server  │  REST API  │  SDK              │
│                     │            │                    │
│  ┌──────────────────┴────────────┴────────────────┐ │
│  │              Policy Engine                      │ │
│  │  (simulation, spending limits, allowlists)      │ │
│  └──────────────────┬─────────────────────────────┘ │
│                     │                                │
│  ┌──────────────────▼─────────────────────────────┐ │
│  │           Signing Enclave (isolated process)    │ │
│  │  (key decryption, tx signing, key wiping)       │ │
│  └──────────────────┬─────────────────────────────┘ │
│                     │                                │
│  ┌──────────────────▼─────────────────────────────┐ │
│  │              Wallet Vault (filesystem)           │ │
│  │  ~/.lws/wallets/*.json                          │ │
│  │  ~/.lws/policies/*.json                         │ │
│  │  ~/.lws/config.json                             │ │
│  └─────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Specification Documents

The standard is organized into modular sub-specifications, each covering a distinct concern:

| Document | Description |
|---|---|
| [01 - Storage Format](docs/01-storage-format.md) | Encrypted keystore format, file layout, and vault structure |
| [02 - Chain-Agnostic Addressing](docs/02-chain-agnostic-addressing.md) | CAIP-based chain and account identification |
| [03 - Signing Interface](docs/03-signing-interface.md) | The core `sign`, `signAndSend`, and `simulate` operations |
| [04 - Policy Engine](docs/04-policy-engine.md) | Policy types, evaluation, and enforcement model |
| [05 - Key Isolation](docs/05-key-isolation.md) | Process isolation, enclave architecture, and threat model |
| [06 - Agent Access Layer](docs/06-agent-access-layer.md) | MCP server, REST API, and SDK interface for agents |
| [07 - Multi-Chain Support](docs/07-multi-chain-support.md) | Chain plugins, derivation paths, and transaction builders |
| [08 - Wallet Lifecycle](docs/08-wallet-lifecycle.md) | Creation, import, export, backup, recovery, and migration |

## Core Types

All types use [CAIP](https://chainagnostic.org/) identifiers and are defined in TypeScript for clarity. Implementations may use any language.

```typescript
// === Identifiers ===

/** CAIP-2 chain identifier. e.g. "eip155:1", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" */
type ChainId = `${string}:${string}`;

/** CAIP-10 account identifier. e.g. "eip155:1:0xab16a96d..." */
type AccountId = `${ChainId}:${string}`;

/** Wallet identifier (UUID v4) */
type WalletId = string;

// === Wallet Descriptor ===

interface WalletDescriptor {
  id: WalletId;
  name: string;
  createdAt: string;                    // ISO 8601
  chainType: ChainType;                 // "evm" | "solana" | "tron" | "cosmos" | "bitcoin" | ...
  accounts: AccountDescriptor[];
  policyIds: string[];
  metadata: Record<string, unknown>;    // extensible
}

interface AccountDescriptor {
  accountId: AccountId;                 // CAIP-10
  address: string;                      // chain-native address
  derivationPath: string;              // BIP-44 path, e.g. "m/44'/60'/0'/0/0"
  chainId: ChainId;                    // CAIP-2
}

// === Operations ===

interface SignRequest {
  walletId: WalletId;
  chainId: ChainId;
  transaction: SerializedTransaction;   // chain-specific serialized tx
  simulate?: boolean;                   // run simulation before signing (default: true)
}

interface SignResult {
  signature: string;                    // hex or base64 encoded
  signedTransaction: string;           // fully signed, ready to broadcast
  simulationResult?: SimulationResult;
}

interface SignAndSendRequest extends SignRequest {
  maxRetries?: number;
  confirmations?: number;              // blocks to wait
}

interface SignAndSendResult extends SignResult {
  transactionHash: string;
  blockNumber?: number;
  status: "confirmed" | "pending" | "failed";
}

interface SignMessageRequest {
  walletId: WalletId;
  chainId: ChainId;
  message: string | Uint8Array;
  encoding?: "utf8" | "hex";
}

interface SignMessageResult {
  signature: string;
}

// === Simulation ===

interface SimulationResult {
  success: boolean;
  gasEstimate?: string;
  stateChanges?: StateChange[];
  error?: string;
  warnings?: string[];
}

interface StateChange {
  type: "transfer" | "approval" | "mint" | "burn" | "contract_call";
  asset?: string;                      // token address or "native"
  from?: string;
  to?: string;
  amount?: string;
  description: string;
}

// === Policy ===

interface Policy {
  id: string;
  name: string;
  rules: PolicyRule[];
  action: "deny" | "warn";            // deny = block tx, warn = log but allow
}

type PolicyRule =
  | { type: "max_value"; chainId: ChainId; asset: string; maxAmount: string; period?: Duration }
  | { type: "allowlist"; addresses: string[] }
  | { type: "denylist"; addresses: string[] }
  | { type: "chain_restriction"; allowedChains: ChainId[] }
  | { type: "contract_allowlist"; contracts: string[] }
  | { type: "require_simulation" }
  | { type: "time_restriction"; allowedHours: { start: number; end: number; timezone: string } }
  | { type: "custom"; evaluator: string };    // path to custom evaluator module

type Duration = "per_tx" | "hourly" | "daily" | "weekly" | "monthly";
```

## Quick Start

```bash
# Install the reference implementation
npm install -g @lws/cli

# Create a new wallet
lws wallet create --name "agent-treasury" --chain evm

# List wallets
lws wallet list

# Attach a policy
lws policy create --name "safe-agent" \
  --rule 'max_value:eip155:8453:native:1.0:daily' \
  --rule 'require_simulation'
lws policy attach --wallet agent-treasury --policy safe-agent

# Sign a transaction (from any tool that speaks LWS)
lws tx sign --wallet agent-treasury --chain eip155:8453 --tx <serialized_tx>

# Start the MCP server (for agent access)
lws serve --mcp

# Start the REST API (for programmatic access)
lws serve --rest --port 8402
```

## Prior Art and Influences

| Project | What LWS borrows |
|---|---|
| [x402](https://x402.org) | Scheme/network/transport separation; open spec structure with templates |
| [Privy](https://privy.io) | Policy engine design; key sharding concepts; CAIP-2 chain identifiers |
| [Coinbase AgentKit](https://github.com/coinbase/agentkit) | ActionProvider/WalletProvider pattern; MCP tool exposure |
| [Ethereum Keystore v3](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage) | Encrypted keystore JSON format (scrypt + AES-128-CTR) |
| [W3C Universal Wallet](https://w3c-ccg.github.io/universal-wallet-interop-spec/) | lock/unlock/add/remove interface; content type model |
| [Solana Wallet Standard](https://github.com/anza-xyz/wallet-standard) | Feature-based capability registration |
| [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) | Session keys; programmable validation; paymaster gas sponsorship |
| [CAIP Standards](https://chainagnostic.org/) | Chain-agnostic identifiers (CAIP-2, CAIP-10, CAIP-25, CAIP-27) |
| [WalletConnect v2](https://specs.walletconnect.com/2.0) | Session authorization model; relay architecture |
| [Crossmint](https://crossmint.com) | Dual-key model (owner + agent); onchain policy enforcement |
| [Lit Protocol / Vincent](https://developer.litprotocol.com/) | Decentralized key management; IPFS-published action policies |
| [Turnkey](https://turnkey.com) | TEE-based signing; sub-100ms latency targets |

## Contributing

LWS follows x402's contribution model. To propose a new chain plugin, policy type, or access layer transport:

1. Copy the relevant template from `docs/templates/`
2. Fill in the specification following the template structure
3. Submit a pull request with the new document in `docs/`

## License

This specification is released under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/) — dedicated to the public domain.
