# x402 Marketplace Integration Guide

> How to use OWS as the wallet layer for agent marketplaces that accept x402 payments.

This guide walks through connecting an OWS wallet to an x402-enabled agent marketplace. It uses [Agoragentic](https://agoragentic.com) as a concrete example — a live production marketplace where AI agents buy and sell capabilities using USDC on Base L2 — but the pattern applies to any x402-enabled service.

## Prerequisites

- OWS installed (`npm install -g @open-wallet-standard/core` or `curl -fsSL https://docs.openwallet.sh/install.sh | bash`)
- USDC on Base L2 (to fund the wallet)

## 1. Create a Wallet

```bash
ows wallet create --name "marketplace-agent"
```

This creates an encrypted wallet at `~/.ows/wallets/` with addresses for all 9 supported chains. The EVM address will be used for Base L2 USDC payments.

## 2. Fund with USDC

```bash
# Option A: MoonPay deposit (fiat → USDC, auto-converts)
ows fund deposit --wallet "marketplace-agent" --chain base

# Option B: Send USDC directly to your EVM address
ows wallet list  # shows your Base address
```

Check balance:

```bash
ows fund balance --wallet "marketplace-agent" --chain base
```

## 3. Create a Safety Policy

Policies gate what agents can do with the wallet. For a marketplace buyer, restrict to Base L2 only and add an expiry:

```bash
cat > marketplace-policy.json << 'EOF'
{
  "id": "marketplace-base-only",
  "name": "Marketplace Buyer — Base L2 Only",
  "version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "action": "deny"
}
EOF
ows policy create --file marketplace-policy.json
```

For tighter control, add a custom executable policy for spend caps. See [Policy Engine](03-policy-engine.md) for details.

## 4. Create an Agent API Key

Create a scoped API key attached to the wallet and policy:

```bash
ows key create --name "buyer-agent" --wallet marketplace-agent --policy marketplace-base-only
# => ows_key_a1b2c3d4...  (save this — shown once)
```

The agent uses this token for all signing operations. It never sees the raw private key.

## 5. Make x402 Payments

### CLI

```bash
# Browse available services
ows pay discover --query "marketplace"

# Make a paid API call — auto-handles 402 → sign → retry
ows pay request "https://agoragentic.com/api/execute" \
  --wallet "marketplace-agent" \
  --method POST \
  --body '{"task": "summarize this text", "input": {"text": "Your content here"}}'
```

The `pay request` flow:

1. Sends the HTTP request
2. If the server returns `402 Payment Required` with x402 headers, OWS reads the payment requirements
3. Signs an EIP-3009 `TransferWithAuthorization` for the requested USDC amount
4. Retries the request with the `X-PAYMENT` header containing the signed authorization
5. Returns the response

### Node.js SDK

```javascript
import { createWallet, signMessage, payRequest } from "@open-wallet-standard/core";

// Create wallet (one-time setup)
const wallet = createWallet("marketplace-agent");

// Make a paid request
const result = await payRequest(
  "https://agoragentic.com/api/execute",
  "marketplace-agent",
  {
    method: "POST",
    body: JSON.stringify({
      task: "summarize this text",
      input: { text: "Your content here" },
    }),
  }
);

console.log(result);
```

### Python SDK

```python
from open_wallet_standard import create_wallet, pay_request

# Create wallet (one-time setup)
wallet = create_wallet("marketplace-agent")

# Make a paid request
result = pay_request(
    "https://agoragentic.com/api/execute",
    "marketplace-agent",
    method="POST",
    body='{"task": "summarize this text", "input": {"text": "Your content here"}}',
)

print(result)
```

## 6. Full Agent Workflow

A typical agent uses OWS as its wallet layer while interacting with the marketplace via standard HTTP or a framework-specific SDK:

```bash
# 1. Register on the marketplace (free — returns an API key)
curl -X POST https://agoragentic.com/api/quickstart \
  -H "Content-Type: application/json" \
  -d '{"name": "my-ows-agent", "type": "buyer"}'
# => { "api_key": "amk_...", "credits": "$5.00" }

# 2. Search for capabilities
curl "https://agoragentic.com/api/capabilities?search=summarize" \
  -H "Authorization: Bearer amk_your_key"

# 3. Execute (API key auth) — for credit-based payments
curl -X POST https://agoragentic.com/api/execute \
  -H "Authorization: Bearer amk_your_key" \
  -H "Content-Type: application/json" \
  -d '{"task": "summarize", "input": {"text": "..."}}'

# 4. Execute (x402 payment) — for on-chain USDC payments
ows pay request "https://agoragentic.com/x402/invoke/CAPABILITY_ID" \
  --wallet "marketplace-agent" \
  --method POST \
  --body '{"input": {"text": "..."}}'
```

## Security Notes

- **Agent API keys are scoped.** Each key is restricted to specific wallets and policies. Agents authenticate with the token; they never see the private key.
- **Policies are pre-signing.** All policy checks happen before any key material is decrypted. If a policy denies the request, the key is never touched.
- **Revocation is instant.** Delete the API key file and the token becomes useless — the encrypted wallet copy is removed.
- **Audit trail.** All signing operations are logged to `~/.ows/logs/audit.jsonl`.

## Related Docs

- [Policy Engine](03-policy-engine.md) — Full policy specification including custom executable policies
- [Agent Access Layer](04-agent-access-layer.md) — Access profiles for agent integration
- [Signing Interface](02-signing-interface.md) — Transaction and message signing API
- [CLI Reference](sdk-cli.md) — Complete CLI command reference
