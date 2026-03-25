<!-- Generated from readme/templates/node.md + readme/partials/ — edit those, then run readme/generate.sh -->

# @open-wallet-standard/core

Local, policy-gated signing and wallet management for every chain.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/open-wallet-standard/core/blob/main/LICENSE)

{{> why-ows}}

## Install

```bash
npm install @open-wallet-standard/core    # Node.js SDK
npm install -g @open-wallet-standard/core # Node.js SDK + CLI (provides `ows` command)
```

The package is **fully self-contained** — it embeds the Rust core via native FFI. Installing globally with `-g` also provides the `ows` CLI.

## Quick Start

```javascript
import { createWallet, signMessage } from "@open-wallet-standard/core";

const wallet = createWallet("agent-treasury");
// => accounts for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, Sui, and XRPL

const sig = signMessage("agent-treasury", "evm", "hello");
console.log(sig.signature);
```

### CLI

```bash
# Create a wallet (derives addresses for the current auto-derived chain set)
ows wallet create --name "agent-treasury"

# Sign a message
ows sign message --wallet agent-treasury --chain evm --message "hello"

# Sign a transaction
ows sign tx --wallet agent-treasury --chain evm --tx "deadbeef..."
```

{{> supported-chains}}

{{> cli-reference}}

{{> architecture}}

## Documentation

The full spec and docs are available at [openwallet.sh](https://openwallet.sh) and in the [GitHub repo](https://github.com/open-wallet-standard/core).

## License

MIT