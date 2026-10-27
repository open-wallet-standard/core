# Solana Pulse policy: check a Solana transaction before an agent signs it

A [custom executable policy](../../docs/03-policy-engine.md#custom-executable-policies) for Solana. Before an
agent's API key signs a Solana transaction, the policy sends the transaction to
[Solana Pulse](https://github.com/Timothymycompc/solana-pulse-ai-agent-gateway)'s `check_tx`, which simulates it
on mainnet and answers **OK**, **REVIEW** or **BLOCK** with its reasons: token approvals that let another wallet
drain an account, authority changes, unknown programs, an expired blockhash, a transaction that already landed,
and more. Only OK is signed.

```
agent ──sign_transaction──▶ OWS ──PolicyContext (raw_hex)──▶ pulse-policy.mjs ──tx (base64)──▶ check_tx
                             ▲                                      │
                             └──────── { "allow": true|false, "reason" } ◀── OK / REVIEW / BLOCK
```

## Setup

```bash
chmod +x examples/solana-pulse-policy/pulse-policy.mjs
# Put the script's absolute path in "executable", then register the policy:
ows policy create --file examples/solana-pulse-policy/policy.json
ows key create --name my-agent --wallet my-wallet --policy solana-pulse-check
```

Give the agent the `ows_key_...` token as usual. Needs Node.js 20+ (built-in `fetch`). No dependencies.

## What it allows

| Request | Result |
|---|---|
| Solana `sign_transaction`, check_tx says OK | allowed |
| Solana `sign_transaction`, REVIEW or BLOCK | denied, with Pulse's summary as the reason |
| check_tx unreachable, timed out, HTTP error, or no verdict | denied (fails closed) |
| Solana `sign_message` / `sign_hash` | denied, unless `config.allow_messages` is `true` (see below) |
| `read_balance` (no signature) | allowed |
| Another chain | allowed by this executable; the policy's `allowed_chains` rule stops the key signing there |

**Why messages are denied on Solana.** OWS signs Solana messages without a prefix, so a `sign_message` over a
transaction's message bytes is a valid signature for that transaction. Allowing it would let an agent skip the
check. Turn it on only if the agent needs off-chain message signing.

## Config (the policy file's `config`)

| Field | Default | Meaning |
|---|---|---|
| `allow` | `["OK"]` | Verdicts that may be signed. Adding `"REVIEW"` trades safety for fewer refusals. |
| `endpoint` | Pulse's hosted `check_tx` | Point it at a self-hosted Pulse (the server is MIT-licensed). |
| `timeout_ms` | `20000` | How long to wait before denying. |
| `allow_messages` | `false` | Permit Solana `sign_message` / `sign_hash` without a check. |

## Cost and privacy

- The hosted `check_tx` gives each caller 25 free calls a day, then costs $0.02 in USDC per call via x402. This
  script doesn't pay, so after the free calls it denies; set `PULSE_API_KEY` (sent as `x-api-key`) for a key
  without the daily limit, or self-host.
- The unsigned transaction is sent to the endpoint. Nothing is signed or sent to the network by the check.
- OK means none of the risks Pulse checks for were found. It doesn't make a transaction safe, and REVIEW often
  just means "rebuild with a fresh blockhash".

## How it was tested

**Offline**, with a local stand-in for check_tx (no network, same result every run):

```bash
node --test examples/solana-pulse-policy/test.mjs     # 7 tests: verdicts, fail-closed paths, messages, API key
```

**End to end through OWS itself** (ows 1.4.3 `6a2f782`, Node 24, Solana mainnet, 2026-10-27 UTC). A throwaway
wallet, this policy registered with `ows policy create`, an API key from `ows key create`, then `ows sign tx`
with the key, on test transactions rebuilt from Pulse's recorded fixtures (none was ever sent):

| Time (UTC) | Request | OWS result |
|---|---|---|
| 07:22:52 | 0.01 SOL transfer, fresh blockhash | signed |
| 07:22:25 | the same transfer, blockhash a few minutes old | denied: `REVIEW: The blockhash has expired, so the network would reject this...` |
| 07:22:28 | token approval that lets another wallet move an account's tokens at any time | denied: `BLOCK: Instruction 2 lets 9WzD... move up to 1000000000000 base units from token account FzbcyE... This is the most common wallet-drainer pattern.` |
| 07:24:27 | same key, `ows sign tx --chain base` | denied: `chain eip155:8453 not in allowlist` |
| 07:24:30 | same key, `ows sign message --chain solana` | denied: `sign_message on Solana can authorize a transaction without a check...` |
