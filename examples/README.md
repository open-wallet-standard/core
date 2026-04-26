# OWS Examples

Runnable examples for common OWS use cases.

## Prerequisites

    npm install -g @open-wallet-standard/core
    ows wallet create --name my-wallet

Get test USDC on Base Sepolia: https://faucet.circle.com

## Examples

| File | Description |
|---|---|
| [x402-pay-request.js](x402-pay-request.js) | Pay an x402-enabled API endpoint |
| [x402-discover-services.js](x402-discover-services.js) | Discover payable services in the marketplace |
| [agent-with-policy.js](agent-with-policy.js) | Create a policy-gated API key for an agent |

## Running

    node examples/x402-pay-request.js
    node examples/x402-discover-services.js
    node examples/agent-with-policy.js
