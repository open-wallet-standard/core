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

Minimal Python example — cap the ADA one transaction moves out of the wallet's own
addresses:

    import json, sys
    ctx = json.load(sys.stdin)
    if ctx["request_type"] == "sign_typed_data":  # no transaction to cap
        json.dump({"allow": False, "reason": "typed data not permitted"}, sys.stdout)
        sys.exit(0)

    tx = ctx["transaction"]
    owned = {"addr1qx2f..."}
    limit = 5_000_000  # 5 ADA
    out = -sum(int(amount)
               for effect in tx["effects"] if effect["address"] in owned
               for asset, amount in effect["diff"]
               if asset == "lovelace" and int(amount) < 0)
    if out > limit:
        json.dump({"allow": False, "reason": "Value exceeds limit"}, sys.stdout)
    else:
        json.dump({"allow": True}, sys.stdout)

Reference it in the policy file:

    {
      "id": "value-limit",
      "name": "Max 5 ADA per transaction",
      "version": 1,
      "created_at": "2026-01-01T00:00:00Z",
      "rules": [{ "type": "allowed_chains", "chain_ids": ["cip34:1-764824073"] }],
      "executable": "/home/user/.ows/plugins/policies/value-limit.py",
      "action": "deny"
    }

## 5. PolicyContext Fields

| Field | Description |
|---|---|
| chain_id | CAIP-2 chain ID (e.g. eip155:8453) |
| wallet_id | Wallet UUID |
| api_key_id | API key UUID |
| request_type | sign_transaction, sign_message, sign_hash, sign_typed_data or read_balance; always present |
| transaction | Absent for sign_typed_data; branch on request_type, not on this field's absence |
| transaction.effects | Per-address asset movement; empty unless the chain's signer implements flow analysis (Cardano today) |
| transaction.effects[].diff | [asset, amount] pairs; amount is a signed decimal string in the smallest unit |
| transaction.chain_extra | Chain-specific detail effects cannot carry; present only when a chain fills it |
| transaction.raw_hex | Raw unsigned payload hex |
| spending.daily_total | Cumulative value signed today (wei) |
| timestamp | ISO-8601 signing request time |

`transaction.to` and `transaction.value` were documented here previously. Neither was
ever populated by any chain, so a policy reading them always saw `null`; `effects`
replaces them.

## 6. Testing Policies

Test executable policies without real signing:

    echo '{"chain_id": "cip34:1-764824073", "wallet_id": "test", "api_key_id": "test",
      "request_type": "sign_transaction",
      "transaction": {"raw_hex": "84a4",
        "effects": [{"address": "addr1qx2f...", "diff": [["lovelace", "-6000000"]]}]},
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
