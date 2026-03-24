# OWS Examples

This directory contains example integrations and plugins for the [Open Wallet Standard](../README.md).

## Available examples

### [thoughtproof-policy](./thoughtproof-policy/)

A pre-signing reasoning verification policy that calls the [ThoughtProof](https://thoughtproof.ai) API before allowing OWS to sign any transaction.

- Verifies transaction intent using AI reasoning
- Blocks transactions that fail reasoning checks (BLOCK or UNCERTAIN verdicts)
- Fails open on API errors to preserve liveness
- No external dependencies beyond Node.js built-in `fetch`

**Quick start:**

```bash
ows policy create --file examples/thoughtproof-policy/policy.json
ows key create --name "my-agent" --wallet my-wallet --policy thoughtproof-reasoning
```

See the [thoughtproof-policy README](./thoughtproof-policy/README.md) for full details.
