# 04 - Policy Engine

> How transaction policies are defined, evaluated, and enforced before any key material is touched.

## Design Decision

**LWS uses a two-tier access model: the wallet owner has unrestricted (sudo) access, while agents authenticate via API keys whose attached policies are evaluated before the signing enclave is invoked. Policies are attached to API keys, not wallets — wallets are dumb containers for key material. Default behavior is deny-by-default when a policy is attached to a key — only transactions that pass all of the key's policies are signed.**

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

## Policy Executable Protocol

A policy is any executable program. LWS invokes the executable, pipes a `PolicyContext` JSON object to its stdin, and reads a `PolicyResult` JSON object from its stdout.

This follows the Unix philosophy and mirrors the enclave protocol already used by LWS (JSON-RPC over stdio). Policies can be written in any language — shell scripts, Python, Go, Rust, JavaScript — whatever the operator prefers.

Because a policy is arbitrary code, it can perform any logic before returning a verdict — including making RPC calls to simulate the transaction, querying on-chain state, checking balances, calling external APIs, or consulting a local database. LWS core does not provide these capabilities directly; they are delegated to the policy layer.

**Invocation:**

```
echo '<PolicyContext JSON>' | /path/to/policy-executable
```

**Rules:**
- The executable receives the full `PolicyContext` as a single JSON object on stdin
- The executable MUST write a single `PolicyResult` JSON object to stdout
- A non-zero exit code is treated as a denial (equivalent to `{ "allow": false, "reason": "process exited with code N" }`)
- Stderr is captured and logged to the audit log but does not affect the verdict

## Policy File Format

Policies are JSON files stored in `~/.lws/policies/`:

```json
{
  "id": "safe-agent-policy",
  "name": "Safe Agent Policy",
  "version": 1,
  "created_at": "2026-02-27T10:00:00Z",
  "executable": "/home/user/.lws/plugins/policies/safe-agent.sh",
  "config": {
    "max_daily_spend_wei": "1000000000000000000",
    "allowed_chains": ["eip155:8453", "eip155:84532"]
  },
  "action": "deny"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique policy identifier |
| `name` | string | yes | Human-readable policy name |
| `version` | integer | yes | Policy schema version (currently `1`) |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `executable` | string | yes | Absolute path to the policy executable |
| `config` | object | no | Static configuration passed to the executable as part of `PolicyContext` |
| `action` | string | yes | `"deny"` or `"warn"` — what happens when the policy returns `allow: false` |

The executable MUST be a file with execute permission. Implementations MUST verify the executable exists and is executable at policy attachment time.

## PolicyContext (stdin)

The JSON object piped to the policy executable's stdin:

```json
{
  "transaction": {
    "to": "0x4B0897b0513fdC7C541B6d9D7E929C4e5364D2dB",
    "value": "1000000000000000",
    "data": "0x"
  },
  "chain_id": "eip155:8453",
  "wallet": {
    "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
    "name": "agent-treasury",
    "chain_type": "evm",
    "accounts": [
      {
        "account_id": "eip155:8453:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        "address": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        "chain_id": "eip155:8453"
      }
    ]
  },
  "timestamp": "2026-02-27T10:35:22Z",
  "api_key_id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
}
```

| Field | Type | Always Present | Description |
|---|---|---|---|
| `transaction` | object | yes | The chain-specific serialized transaction being evaluated |
| `chain_id` | string | yes | CAIP-2 chain identifier |
| `wallet` | object | yes | Wallet descriptor (id, name, chain_type, accounts — never key material) |
| `timestamp` | string | yes | ISO 8601 timestamp of the signing request |
| `api_key_id` | string | yes | The ID of the API key making this request |

The `wallet` field never contains private keys, mnemonics, or encryption parameters. It is a subset of the wallet descriptor containing only public metadata.

The policy executable can use `api_key_id` to apply per-agent logic (e.g., different spending limits for different agents). The static `config` from the policy file is resolved by the policy engine and merged into the executable's environment — it is not passed through `PolicyContext`.

## PolicyResult (stdout)

The JSON object the policy executable writes to stdout:

```json
{
  "allow": true
}
```

Or on denial:

```json
{
  "allow": false,
  "reason": "Daily spending limit exceeded: 1.5 ETH sent, limit is 1.0 ETH"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `allow` | boolean | yes | `true` to permit the transaction, `false` to deny |
| `reason` | string | no | Human-readable explanation (logged to audit log; returned in error on denial) |

## Timeout and Failure Semantics

| Scenario | Behavior |
|---|---|
| Executable exits with code 0, valid JSON on stdout | Use the `PolicyResult` as the verdict |
| Executable exits with non-zero code | **Deny.** Treat as `{ "allow": false }`. Stderr is logged. |
| Executable does not produce valid JSON on stdout | **Deny.** Log a parse error to the audit log. |
| Executable does not exit within 5 seconds | **Deny.** Kill the process. Log a timeout to the audit log. |
| Executable not found or not executable | **Deny.** Log an error. This is checked at policy attachment time to fail early. |

The default-deny stance ensures that policy failures are never silently bypassed.

## Policy Actions

| Action | Behavior |
|---|---|
| `deny` | Block the transaction and return a `POLICY_DENIED` error |
| `warn` | Log a warning to the audit log but allow the transaction to proceed |

## Who Is Evaluated?

LWS uses a two-tier access model:

| Caller | Authentication | Policy Evaluation |
|---|---|---|
| **Owner** | Passphrase/passkey | **None.** The owner has unrestricted (sudo) access to all wallets. No policies are evaluated. |
| **Agent (API key)** | `lws_key_...` token | **All policies attached to the API key** are evaluated. Every policy must allow the transaction (AND semantics). |

The owner can always sign any transaction on any wallet — if they want self-imposed limits, they create an API key for themselves and use that instead.

## Policy Attachment

Policies are attached to API keys, not wallets. When an API key is created, it is scoped to specific wallets and policies:

```bash
# Create a policy
lws policy create --file safe-agent-policy.json

# Create an API key with wallet scope and policy attachment
lws key create --name "claude-agent" --wallet agent-treasury --policy safe-agent-policy
# => lws_key_a1b2c3d4e5f6...  (shown once, store securely)
```

An API key can have multiple policies attached. All attached policies are evaluated — every policy must allow the transaction for it to proceed (AND semantics). Evaluation short-circuits on the first denial. All denials are logged to the audit log.

## Example: Spending Limit Policy (Shell Script)

To illustrate the protocol, here is a minimal spending-limit policy implemented as a shell script. This is not a built-in type — it is a user-provided executable like any other policy.

```bash
#!/usr/bin/env bash
# spending-limit.sh — Deny transactions over 1 ETH (1e18 wei)
set -euo pipefail

MAX_WEI="1000000000000000000"

# Read PolicyContext from stdin
CONTEXT=$(cat)

# Extract the transaction value (defaults to "0" if absent)
VALUE=$(echo "$CONTEXT" | jq -r '.transaction.value // "0"')

# Compare (jq handles big-number string comparison)
EXCEEDS=$(echo "$CONTEXT" | jq --arg max "$MAX_WEI" --arg val "$VALUE" \
  '($val | tonumber) > ($max | tonumber)')

if [ "$EXCEEDS" = "true" ]; then
  echo '{"allow": false, "reason": "Transaction value exceeds 1 ETH limit"}'
  exit 0
fi

echo '{"allow": true}'
```

The corresponding policy file:

```json
{
  "id": "spending-limit",
  "name": "1 ETH Per-Transaction Limit",
  "version": 1,
  "created_at": "2026-02-27T10:00:00Z",
  "executable": "/home/user/.lws/plugins/policies/spending-limit.sh",
  "action": "deny"
}
```

A more sophisticated spending-limit policy that tracks cumulative spending over time would maintain its own state file — that is an implementation detail of the policy executable, not a concern of the core spec.

## References

- [Privy Policy Engine](https://privy.io/blog/turning-wallets-programmable-with-privy-policy-engine)
- [Crossmint Onchain Policy Enforcement](https://blog.crossmint.com/ai-agent-wallet-architecture/)
- [ERC-4337 Session Keys](https://eips.ethereum.org/EIPS/eip-4337)
- [Lit Protocol / Vincent Policy Framework](https://spark.litprotocol.com/meet-vincent-an-agent-wallet-and-app-store-framework-for-user-owned-automation/)
- [Turnkey Granular Policies](https://docs.turnkey.com)
- [Coinbase Agentic Wallet Guardrails](https://www.coinbase.com/developer-platform/discover/launches/agentic-wallets)
