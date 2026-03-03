# Local Wallet Standard (LWS)

A specification and reference implementation for secure, local-first crypto wallet management — designed for AI agents.

## Motivation

AI agents increasingly need to interact with blockchains: signing transactions, managing accounts, and moving value across chains. Existing wallet infrastructure was built for humans clicking buttons in browser extensions, not for programmatic agents operating autonomously.

LWS addresses this gap. It defines a minimal, chain-agnostic standard for wallet operations where:

- **Private keys never leave the local machine.** Keys are stored in encrypted Ethereum Keystore v3 format with strict filesystem permissions — no remote servers, no browser extensions.
- **Agents interact through structured protocols.** The primary interface is an [MCP](https://modelcontextprotocol.io) server, giving AI agents native wallet access without custom integrations.
- **Transaction policies are enforced before signing.** A pre-signing policy engine gates every operation, so agents can be granted scoped, auditable access to wallet capabilities.
- **One interface covers all chains.** CAIP-2/CAIP-10 addressing and a unified signing interface abstract away chain-specific details across EVM, Solana, Bitcoin, Cosmos, and Tron.

## Repo Structure

```
├── docs/                        # The specification (8 documents)
│   ├── 01-storage-format.md         # Vault layout, Keystore v3, filesystem permissions
│   ├── 02-chain-agnostic-addressing.md  # CAIP-2/CAIP-10 standards
│   ├── 03-signing-interface.md      # sign, signAndSend, signMessage operations
│   ├── 04-policy-engine.md          # Pre-signing transaction policies
│   ├── 05-key-isolation.md          # HD derivation paths and key separation
│   ├── 06-agent-access-layer.md     # MCP server, REST API, library interfaces
│   ├── 07-multi-chain-support.md    # Multi-chain account management
│   └── 08-wallet-lifecycle.md       # Creation, recovery, deletion, lifecycle events
│
├── lws/                         # Rust reference implementation
│   └── crates/
│       ├── lws-core/                # Core types, CAIP parsing, config (zero crypto deps)
│       └── lws-signer/             # Signing, HD derivation, chain-specific implementations
│
├── sdks/                        # Client SDKs for the LWS REST API
│   ├── python/                      # Python SDK (async + sync, httpx)
│   └── typescript/                  # TypeScript SDK (@lws/sdk, native fetch)
│
└── website/                     # Documentation site (localwalletstandard.org)
```

## Getting Started

Read the spec starting with [`docs/01-storage-format.md`](docs/01-storage-format.md), or browse it at [localwalletstandard.org](https://localwalletstandard.org).

Install the reference implementation:

```bash
curl -sSf https://openwallet.sh/install.sh | bash
```

Or build from source:

```bash
cd lws
cargo build --workspace --release
cargo test --workspace
```

## SDKs

LWS provides client SDKs that wrap the REST API (`http://127.0.0.1:8402`) with full type safety.

### Python

```bash
pip install lws
```

```python
from lws import LWSClient, ChainType

async with LWSClient(api_key="lws_key_...") as client:
    wallets = await client.list_wallets()
    result = await client.sign_and_send(
        wallet_id=wallets[0].id,
        chain_id="eip155:8453",
        transaction={"to": "0x...", "value": "1000000000000000"},
    )
    print(result.tx_hash)
```

A synchronous client is also available:

```python
from lws import LWSClientSync

with LWSClientSync(api_key="lws_key_...") as client:
    wallets = client.list_wallets()
```

### TypeScript

```bash
npm install @lws/sdk
```

```typescript
import { LWSClient } from "@lws/sdk";

const client = new LWSClient({ apiKey: "lws_key_..." });

const wallets = await client.listWallets();
const result = await client.signAndSend({
  wallet_id: wallets[0].id,
  chain: "eip155:8453",
  transaction: { to: "0x...", value: "1000000000000000" },
});

console.log(result.tx_hash);
```

Both SDKs require Node 18+ (TypeScript) or Python 3.10+ (Python). See the full API in `sdks/python/` and `sdks/typescript/`.

## License

MIT
