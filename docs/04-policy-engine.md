# 04 - Policy Engine

> How transaction policies are defined, evaluated, and enforced before any key material is touched.

## Design Decision

**LWS enforces policies as a mandatory gate between the signing request and key decryption. Policies are evaluated before the signing enclave is invoked. Default behavior is deny-by-default when a policy is attached — only transactions that pass all rules are signed.**

### Why Pre-Signing Policy Enforcement

We studied three enforcement models:

| Model | Where Enforced | Used By | Trade-offs |
|---|---|---|---|
| Application-layer | In the calling app | Most agent frameworks | Bypassable; the app can ignore its own rules |
| Smart contract | On-chain | Crossmint (ERC-4337), Lit Protocol | Strong but chain-specific; gas cost for policy checks |
| **Pre-signing gate** | In the wallet process | Privy, Turnkey | Universal across chains; not bypassable without vault access |

LWS uses pre-signing enforcement because:
1. It works identically for all chains (no smart contract deployment needed)
2. It prevents key material from being accessed for unauthorized transactions
3. It complements on-chain enforcement (use both for defense in depth)
4. Following Privy's model: policies are evaluated inside the signing enclave's trust boundary

## Policy Structure

Policies are JSON files stored in `~/.lws/policies/`:

```json
{
  "id": "safe-agent-policy",
  "name": "Safe Agent Policy",
  "version": 1,
  "created_at": "2026-02-27T10:00:00Z",
  "rules": [
    {
      "type": "max_value",
      "chain_id": "eip155:8453",
      "asset": "native",
      "max_amount": "1000000000000000000",
      "period": "daily"
    },
    {
      "type": "max_value",
      "chain_id": "eip155:8453",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "max_amount": "100000000",
      "period": "per_tx"
    },
    {
      "type": "contract_allowlist",
      "contracts": [
        "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "eip155:8453:0x4200000000000000000000000000000000000006"
      ]
    },
    {
      "type": "require_simulation"
    },
    {
      "type": "chain_restriction",
      "allowed_chains": ["eip155:8453", "eip155:84532"]
    }
  ],
  "action": "deny"
}
```

## Rule Types

### `max_value` — Spending Limits

Caps the value of transactions over a configurable time period.

```json
{
  "type": "max_value",
  "chain_id": "eip155:8453",
  "asset": "native",
  "max_amount": "1000000000000000000",
  "period": "daily"
}
```

| Field | Type | Description |
|---|---|---|
| `chain_id` | ChainId | Scope to a specific chain, or `"*"` for all chains |
| `asset` | string | Token contract address (CAIP-10) or `"native"` |
| `max_amount` | string | Maximum amount in the asset's smallest unit |
| `period` | Duration | `"per_tx"`, `"hourly"`, `"daily"`, `"weekly"`, `"monthly"` |

Spending is tracked in `~/.lws/state/spending.json`, a rolling ledger of signed transaction values keyed by `(wallet_id, chain_id, asset, period)`.

### `allowlist` — Recipient Allowlist

Only allows transactions to specified addresses.

```json
{
  "type": "allowlist",
  "addresses": [
    "eip155:8453:0x4B0897b0513fdC7C541B6d9D7E929C4e5364D2dB",
    "eip155:8453:0x1234567890abcdef1234567890abcdef12345678"
  ]
}
```

Addresses use CAIP-10 format. A transaction to any address not in the list is denied.

### `denylist` — Recipient Denylist

Blocks transactions to specified addresses (known scam contracts, sanctioned addresses, etc.).

```json
{
  "type": "denylist",
  "addresses": [
    "eip155:1:0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
  ]
}
```

### `chain_restriction` — Allowed Chains

Limits which chains a wallet can transact on.

```json
{
  "type": "chain_restriction",
  "allowed_chains": ["eip155:8453", "eip155:84532"]
}
```

### `contract_allowlist` — Smart Contract Allowlist

Only allows interactions with specified smart contracts. Applies to the `to` field of transactions with `data` (i.e., contract calls).

```json
{
  "type": "contract_allowlist",
  "contracts": [
    "eip155:8453:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  ]
}
```

### `require_simulation` — Mandatory Simulation

Requires that a transaction simulation succeeds before signing. If simulation fails or returns warnings, the transaction is denied.

```json
{
  "type": "require_simulation"
}
```

### `time_restriction` — Time-Based Access

Limits when transactions can be signed.

```json
{
  "type": "time_restriction",
  "allowed_hours": {
    "start": 9,
    "end": 17,
    "timezone": "America/New_York"
  }
}
```

### `custom` — Custom Evaluator

Points to a JavaScript/TypeScript module that implements a custom policy rule.

```json
{
  "type": "custom",
  "evaluator": "~/.lws/plugins/custom-rules/check-slippage.js"
}
```

The evaluator module MUST export a function with the following signature:

```typescript
export async function evaluate(context: PolicyContext): Promise<PolicyResult> {
  // context.transaction — the transaction being evaluated
  // context.simulation — simulation result (if available)
  // context.wallet — wallet descriptor
  // context.spending — current spending state
  return { allow: true };  // or { allow: false, reason: "..." }
}

interface PolicyContext {
  transaction: SerializedTransaction;
  simulation?: SimulationResult;
  wallet: WalletDescriptor;
  spending: SpendingState;
  chainId: ChainId;
}

interface PolicyResult {
  allow: boolean;
  reason?: string;
}
```

## Evaluation Order

1. **Chain restriction** — is this chain allowed?
2. **Denylist** — is the recipient blocked?
3. **Allowlist** — is the recipient permitted? (skipped if no allowlist rule)
4. **Contract allowlist** — is the contract permitted? (skipped for simple transfers)
5. **Simulation** — does the transaction succeed? (if `require_simulation`)
6. **Max value** — would this exceed spending limits?
7. **Time restriction** — is the current time within allowed hours?
8. **Custom evaluators** — do all custom rules pass?

Evaluation short-circuits on the first denial. All denials are logged to the audit log.

## Policy Actions

| Action | Behavior |
|---|---|
| `deny` | Block the transaction and return a `POLICY_DENIED` error |
| `warn` | Log a warning to the audit log but allow the transaction to proceed |

## Policy Attachment

Policies are attached to wallets via the `policy_ids` field in the wallet file:

```bash
# CLI
lws policy attach --wallet agent-treasury --policy safe-agent-policy

# Programmatic
await lws.attachPolicy("3198bc9c-...", "safe-agent-policy");
```

A wallet can have at most one policy attached (following Privy's model). The policy can contain multiple rules. To change policies, detach the current one and attach a new one.

## Spending State

Spending is tracked in `~/.lws/state/spending.json`:

```json
{
  "3198bc9c-...": {
    "eip155:8453:native:daily": {
      "amount": "500000000000000000",
      "period_start": "2026-02-27T00:00:00Z",
      "period_end": "2026-02-28T00:00:00Z"
    }
  }
}
```

Period boundaries are UTC-based. When a period expires, the counter resets. The spending state file has the same `0600` permissions as wallet files.

## References

- [Privy Policy Engine](https://privy.io/blog/turning-wallets-programmable-with-privy-policy-engine)
- [Crossmint Onchain Policy Enforcement](https://blog.crossmint.com/ai-agent-wallet-architecture/)
- [ERC-4337 Session Keys](https://eips.ethereum.org/EIPS/eip-4337)
- [Lit Protocol / Vincent Policy Framework](https://spark.litprotocol.com/meet-vincent-an-agent-wallet-and-app-store-framework-for-user-owned-automation/)
- [Turnkey Granular Policies](https://docs.turnkey.com)
- [Coinbase Agentic Wallet Guardrails](https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets)
