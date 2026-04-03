---
name: riskscope
description: On-chain wallet risk intelligence — scan any Ethereum address or ENS name to get a full risk profile including transaction history, token exposure, counterparty graph, and behavioral flags. Powered by OWS observatory agent and Allium data.
version: 1.0.0
metadata:
  openclaw:
    requires:
      anyBins:
        - ows
        - node
    emoji: "🔍"
    homepage: https://riskscope.xyz
    os:
      - darwin
      - linux
    install:
      - kind: node
        package: "@open-wallet-standard/core"
        bins: [ows]
        label: Install OWS CLI
---

# RiskScope — On-Chain Wallet Risk Intelligence

Scan any Ethereum wallet address or ENS name to generate a full risk report. Every scan is cryptographically signed by an OWS observatory agent wallet. Pay-per-scan via x402 protocol.

**Live Demo:** [riskscope.xyz](https://riskscope.xyz)

## When to use

- Scan a wallet address for risk assessment
- Check on-chain activity and behavioral patterns
- Analyze token exposure and counterparty graph
- Run due diligence on a wallet before a transaction

## Quick Start
```bash
npm install -g @open-wallet-standard/core
ows wallet create --name observatory-agent
ows sign message --wallet observatory-agent --chain evm --message "RiskScope scan: 0x..."
```

## API
```bash
curl -X POST https://riskscope.xyz/api/scan \
  -H "Content-Type: application/json" \
  -d '{"address": "vitalik.eth"}'
```

## Stack

- OWS CLI — observatory-agent wallet signs every scan
- Etherscan V2 API — balance, transactions, token transfers
- Allium Intelligence API — behavioral labels, DeFi/NFT detection
- x402 Protocol — 0.001 USDC per scan
- ENS Resolution — ensdata.net

## Source

- GitHub: [dogiladeveloper/riskscope](https://github.com/dogiladeveloper/riskscope)
- Live: [riskscope.xyz](https://riskscope.xyz)
