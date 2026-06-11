# Policy Engine Implementation Guide

> A practical guide for implementing and integrating the OWS policy engine.
> For the normative specification, see [03-policy-engine.md](03-policy-engine.md).

## Overview

The policy engine gates every agent signing request before any key material
is touched. This guide covers: creating policies, attaching them to API keys,
writing custom executable policies, and testing policy decisions.

## 1. Your First Policy

Create a policy JSON file and register it:

    # my-first-policy.json
    {
      "id": "my-first-policy",
      "name": "Restrict to Base mainnet",
      "version": 1,
      "created_at": "2026-01-01T00:00:00Z",
      "rules": [
        { "type": "allowed_chains", "chain_ids": ["eip155:8453"] }
      ],
      "action": "deny"
    }

    ows policy create --file my-first-policy.json
    ows key create --name "my-agent" --wallet my-wallet --policy my-first-policy

## 2. Common Policy Patterns

### Time-limited access

    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }

### Chain restriction + expiry

    {
      "id": "base-limits",
      "name": "Base Agent Safety Limits",
      "version": 1,
      "created_at": "2026-01-01T00:00:00Z",
      "rules": [
        { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
        { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
      ],
      "action": "deny"
    }

### EIP-712 contract restriction

    {
      "type": "allowed_typed_data_contracts",
      "contracts": ["0x000000000022D473030F116dDEE9F6B43aC78BA3"]
    }

## 3. Multiple Policies on One Key

All attached policies must allow (AND semantics):

    ows key create --name "agent" --wallet treasury --policy base-limits --policy permit2-only

## 4. Custom Executable Policies

Use executables for spending limits, on-chain simulation, or external API calls.
The executable receives PolicyContext JSON on stdin and must write PolicyResult to stdout.

Minimal Python example:

    import json, sys
    ctx = json.load(sys.stdin)
    value = int(ctx["transaction"].get("value", "0"))
    limit = 10_000_000_000_000_000  # 0.01 ETH
    if value > limit:
        json.dump({"allow": False, "reason": "Value exceeds limit"}, sys.stdout)
    else:
        json.dump({"allow": True}, sys.stdout)

Reference it in the policy file:

    {
      "id": "value-limit",
      "name": "Max 0.01 ETH per transaction",
      "version": 1,
      "created_at": "2026-01-01T00:00:00Z",
      "rules": [{ "type": "allowed_chains", "chain_ids": ["eip155:8453"] }],
      "executable": "/home/user/.ows/plugins/policies/value-limit.py",
      "action": "deny"
    }

## 5. PolicyContext Fields

| Field | Description |
|---|---|
| chain_id | CAIP-2 chain ID (e.g. eip155:8453) |
| wallet_id | Wallet UUID |
| api_key_id | API key UUID |
| transaction.to | Recipient address (EVM) |
| transaction.value | Value in wei as string |
| transaction.data | Calldata hex |
| transaction.raw_hex | Raw unsigned transaction hex |
| spending.daily_total | Cumulative value signed today (wei) |
| timestamp | ISO-8601 signing request time |

## 6. Testing Policies

Test executable policies without real signing:

    echo '{"chain_id": "eip155:8453", "wallet_id": "test", "api_key_id": "test",
      "transaction": {"to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C",
        "value": "5000000000000000", "raw_hex": "0x", "data": "0x"},
      "spending": {"daily_total": "0", "date": "2026-01-01"},
      "timestamp": "2026-01-01T00:00:00Z"}' | python3 value-limit.py

## 7. Failure Semantics

The policy engine fails closed. Any failure results in denial:

| Scenario | Result |
|---|---|
| Executable not found | Deny |
| Executable exits non-zero | Deny |
| Executable returns invalid JSON | Deny |
| Executable times out (5s) | Deny |
| Unknown declarative rule type | Deny |

## 8. Managing Policies via CLI

    ows policy list
    ows policy show --id base-limits
    ows policy delete --id base-limits
    ows key list

## References

- [03-policy-engine.md](03-policy-engine.md) - Normative policy engine specification
- [04-agent-access-layer.md](04-agent-access-layer.md) - Agent access and API key management
- [05-key-isolation.md](05-key-isolation.md) - Key isolation and HD derivation
