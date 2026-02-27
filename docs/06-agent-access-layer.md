# 06 - Agent Access Layer

> How AI agents, CLI tools, and applications access LWS wallets through MCP, REST, and library interfaces.

## Design Decision

**LWS exposes wallet operations through three access modes — an MCP server (for AI agents), a REST API (for programmatic access), and a direct library import (for embedded use) — all backed by the same core implementation. The MCP interface is the primary agent access path.**

### Why MCP as the Primary Agent Interface

The [Model Context Protocol](https://modelcontextprotocol.io/) (MCP), open-sourced by Anthropic in November 2024, has become the de facto standard for how AI agents invoke tools. Every major agent framework supports it:

| Framework | MCP Support |
|---|---|
| Claude (Anthropic) | Native |
| OpenAI Agents SDK | Native (March 2025) |
| Coinbase AgentKit | `getMcpTools()` helper |
| LangChain | MCP tool adapter |
| CrewAI | Via LangChain tools |
| OpenClaw | Native MCP integration |

By exposing LWS as an MCP server, any MCP-capable agent can access local wallets without custom integration code. The agent discovers available tools via the MCP `listTools` method and invokes them via `executeTool`.

## MCP Server Tools

The LWS MCP server exposes the following tools:

### `lws_list_wallets`

List all wallets in the vault (no sensitive data exposed).

```json
{
  "name": "lws_list_wallets",
  "description": "List all wallets in the local wallet vault",
  "inputSchema": {
    "type": "object",
    "properties": {
      "chainType": {
        "type": "string",
        "description": "Filter by chain type (evm, solana, etc.)",
        "enum": ["evm", "solana", "tron", "cosmos", "bitcoin"]
      }
    }
  }
}
```

**Returns:** Array of `WalletDescriptor` objects (id, name, accounts, policies — never key material).

### `lws_get_balance`

Get the balance of a wallet account.

```json
{
  "name": "lws_get_balance",
  "description": "Get the native and token balances of a wallet account",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" },
      "chainId": { "type": "string", "description": "CAIP-2 chain ID" },
      "tokens": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Token contract addresses to check (optional)"
      }
    },
    "required": ["walletId", "chainId"]
  }
}
```

### `lws_sign_transaction`

Sign a transaction (with policy enforcement and optional simulation).

```json
{
  "name": "lws_sign_transaction",
  "description": "Sign a transaction using a wallet. Enforces attached policies. Simulates by default.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" },
      "chainId": { "type": "string", "description": "CAIP-2 chain ID" },
      "transaction": {
        "type": "object",
        "description": "Chain-specific transaction object"
      },
      "simulate": { "type": "boolean", "default": true }
    },
    "required": ["walletId", "chainId", "transaction"]
  }
}
```

### `lws_sign_and_send`

Sign and broadcast a transaction.

```json
{
  "name": "lws_sign_and_send",
  "description": "Sign and broadcast a transaction, waiting for confirmation",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" },
      "chainId": { "type": "string" },
      "transaction": { "type": "object" },
      "confirmations": { "type": "number", "default": 1 }
    },
    "required": ["walletId", "chainId", "transaction"]
  }
}
```

### `lws_sign_message`

Sign an arbitrary message for authentication or attestation.

```json
{
  "name": "lws_sign_message",
  "description": "Sign a message with a wallet (for authentication, not transactions)",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" },
      "chainId": { "type": "string" },
      "message": { "type": "string" },
      "typedData": { "type": "object", "description": "EIP-712 typed data (EVM only)" }
    },
    "required": ["walletId", "chainId", "message"]
  }
}
```

### `lws_simulate`

Simulate a transaction without signing.

```json
{
  "name": "lws_simulate",
  "description": "Simulate a transaction to preview state changes and estimate gas",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" },
      "chainId": { "type": "string" },
      "transaction": { "type": "object" }
    },
    "required": ["walletId", "chainId", "transaction"]
  }
}
```

### `lws_get_policy`

View the policy attached to a wallet.

```json
{
  "name": "lws_get_policy",
  "description": "Get the policy rules attached to a wallet",
  "inputSchema": {
    "type": "object",
    "properties": {
      "walletId": { "type": "string" }
    },
    "required": ["walletId"]
  }
}
```

## MCP Server Configuration

Agents configure the LWS MCP server in their MCP settings:

```json
{
  "mcpServers": {
    "lws": {
      "command": "lws",
      "args": ["serve", "--mcp"],
      "env": {
        "LWS_VAULT_PATH": "~/.lws"
      }
    }
  }
}
```

Or for Claude Code specifically, in `~/.claude/claude_code_config.json`:

```json
{
  "mcpServers": {
    "lws": {
      "command": "lws",
      "args": ["serve", "--mcp"]
    }
  }
}
```

## REST API

For non-MCP consumers (web apps, custom scripts, other services), LWS exposes a REST API on `localhost`:

```
POST /v1/wallets                     → Create wallet
GET  /v1/wallets                     → List wallets
GET  /v1/wallets/:id                 → Get wallet descriptor
POST /v1/wallets/:id/sign            → Sign transaction
POST /v1/wallets/:id/sign-and-send   → Sign and broadcast
POST /v1/wallets/:id/sign-message    → Sign message
POST /v1/wallets/:id/simulate        → Simulate transaction
GET  /v1/wallets/:id/balance         → Get balance
GET  /v1/wallets/:id/policy          → Get attached policy
POST /v1/wallets/:id/policy          → Attach policy
DELETE /v1/wallets/:id/policy        → Detach policy
```

### Security: Localhost Only

The REST API MUST bind to `127.0.0.1` only. It MUST NOT be exposed on `0.0.0.0` or any network interface. For remote access, use an SSH tunnel or a reverse proxy with authentication.

### Authentication

The REST API uses a bearer token stored in `~/.lws/config.json`:

```json
{
  "api": {
    "port": 8402,
    "token": "lws_tok_a1b2c3d4e5f6..."
  }
}
```

```bash
curl -H "Authorization: Bearer lws_tok_a1b2c3d4e5f6..." \
  http://127.0.0.1:8402/v1/wallets
```

The token is generated at first startup and stored with `0600` permissions. It provides defense against local privilege escalation (another process on the same machine cannot access wallets without the token).

## Library SDK

For embedding LWS directly into an application (no subprocess or server):

```typescript
import { LWS } from "@lws/core";

const lws = new LWS({ vaultPath: "~/.lws" });
await lws.unlock("passphrase");

const wallets = await lws.listWallets();
const result = await lws.signAndSend({
  walletId: wallets[0].id,
  chainId: "eip155:8453",
  transaction: {
    to: "0x...",
    value: "1000000000000000",
    data: "0x"
  }
});

console.log(result.transactionHash);
```

When used as a library, the signing enclave runs as a worker thread (not a subprocess) for lower latency, but key isolation guarantees are weaker — the keys exist in the same process. For agent use cases, the MCP or REST interfaces (which use subprocess isolation) are recommended.

## Access Layer Comparison

| Mode | Key Isolation | Latency | Best For |
|---|---|---|---|
| MCP Server | Full (subprocess) | ~50ms overhead | AI agents (Claude, GPT, etc.) |
| REST API | Full (subprocess) | ~10ms overhead | Scripts, web apps, other services |
| Library SDK | Partial (worker thread) | Minimal | Embedded applications, CLIs |

## Agent Interaction Example

Here's how an AI agent interacts with LWS through MCP:

```
Agent: "I need to send 0.01 ETH to 0x4B08... on Base"

1. Agent calls lws_list_wallets to find available wallets
   → Returns: [{ id: "3198bc9c-...", name: "agent-treasury", ... }]

2. Agent calls lws_get_balance to check funds
   → Returns: { native: "50000000000000000", ... }  (0.05 ETH)

3. Agent calls lws_simulate to preview the transfer
   → Returns: { success: true, gasEstimate: "21000", stateChanges: [...] }

4. Agent calls lws_sign_and_send to execute
   → Policy engine evaluates (spending limit, allowlist, simulation)
   → Signing enclave decrypts key, signs, wipes
   → Transaction broadcast to Base RPC
   → Returns: { transactionHash: "0xabc...", status: "confirmed" }
```

At no point does the agent see the private key. The MCP tool descriptions tell the agent what operations are available, and the policy engine constrains what operations are permitted.

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Coinbase AgentKit MCP Integration](https://github.com/coinbase/agentkit)
- [Base MCP Server](https://github.com/base/base-mcp)
- [Phala TEE MCP Wallet](https://phala.com/posts/developer-guide-securely-deploy-a-crypto-wallet-mcp-server-on-phala-cloud)
- [OpenClaw MCP Integration](https://ppaolo.substack.com/p/openclaw-system-architecture-overview)
- [Google Cloud: MCP with Web3](https://cloud.google.com/blog/products/identity-security/using-mcp-with-web3-how-to-secure-blockchain-interacting-agents)
- [Privy Server Wallet REST API](https://docs.privy.io/guide/server-wallets/create)
