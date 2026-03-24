# ThoughtProof Reasoning Policy

A pre-signing reasoning verification plugin for the [Open Wallet Standard](../../README.md) Policy Engine.

Before OWS signs any transaction, this policy calls the [ThoughtProof](https://thoughtproof.ai) API to verify whether the transaction's intent is safe and well-reasoned. Transactions that fail the reasoning check are blocked before they reach the signer.

## How it works

```
Agent calls sign()
       │
       ▼
OWS Policy Engine
       │
       │  runs executable, passes PolicyContext via stdin
       ▼
thoughtproof-policy.ts
       │
       │  POST https://api.thoughtproof.ai/v1/check
       │  { claim: "Transfer 0.5 ETH to 0x... on eip155:8453",
       │    stakeLevel: "high", domain: "financial" }
       ▼
ThoughtProof API
       │
       ├─ verdict: ALLOW    → PolicyResult { allow: true }
       │
       ├─ verdict: BLOCK    → PolicyResult { allow: false, reason: "<objection>" }
       │
       ├─ verdict: UNCERTAIN → PolicyResult { allow: false,
       │                        reason: "UNCERTAIN: insufficient evidence — escalate to human review" }
       │
       └─ API error/timeout → PolicyResult { allow: true,
                               reason: "ThoughtProof unavailable — proceeding (liveness fallback)" }
       │
       ▼
OWS Policy Engine
       │
       ├─ allow: true  → sign transaction
       └─ allow: false → deny, return reason to caller
```

## Setup

### 1. Register the policy

```bash
ows policy create --file examples/thoughtproof-policy/policy.json
```

### 2. Attach the policy to an API key

```bash
ows key create --name "my-agent" --wallet my-wallet --policy thoughtproof-reasoning
```

### 3. (Optional) Configure x402 payment wallet

ThoughtProof uses [x402](https://x402.org) for API payments. Set the wallet address to use for automatic payment:

```bash
export THOUGHTPROOF_PAYMENT_WALLET=0xYourWalletAddress
```

If this variable is not set, the API is called without a payment header (works for free-tier / trial usage).

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `THOUGHTPROOF_PAYMENT_WALLET` | No | Wallet address used for x402 micropayments to the ThoughtProof API |

## Example output

### ALLOW

```
[thoughtproof-policy] Checking claim: Transfer 0.5 ETH to 0xABC...123 on eip155:8453
[thoughtproof-policy] Result: allow=true
```

```json
{ "allow": true }
```

### BLOCK

```
[thoughtproof-policy] Checking claim: Transfer 100 ETH to 0xDEAD...BEEF on eip155:1
[thoughtproof-policy] Result: allow=false, reason="Recipient address is flagged as a known scam address"
```

```json
{
  "allow": false,
  "reason": "Recipient address is flagged as a known scam address",
  "policy_id": "thoughtproof-reasoning"
}
```

### UNCERTAIN

```json
{
  "allow": false,
  "reason": "UNCERTAIN: insufficient evidence — escalate to human review",
  "policy_id": "thoughtproof-reasoning"
}
```

### API unavailable (fail-open)

```json
{
  "allow": true,
  "reason": "ThoughtProof unavailable — proceeding (liveness fallback)"
}
```

## Failure modes

| Scenario | Behavior | Rationale |
|---|---|---|
| `verdict: ALLOW` | Proceed | Reasoning verified |
| `verdict: BLOCK` | Deny with objection | Fail-closed on explicit block |
| `verdict: UNCERTAIN` | Deny, escalate | Fail-closed when uncertain |
| API error / timeout | Allow with warning | Fail-open for liveness |
| Parse error on stdin | Allow with warning | Fail-open for liveness |

## Files

| File | Description |
|---|---|
| `thoughtproof-policy.ts` | Main executable — reads stdin, calls API, writes stdout |
| `package.json` | Node.js package manifest (run via `npx tsx`) |
| `policy.json` | OWS policy definition referencing this executable |
