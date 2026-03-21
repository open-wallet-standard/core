## Why OWS

- **Zero key exposure.** Private keys are encrypted at rest, decrypted only inside an isolated signing process. Agents and LLMs never see raw key material.
- **Every chain, one interface.** EVM, Solana, Sui, Bitcoin, Cosmos, Tron, TON — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates every operation — spending limits, allowlists, chain restrictions — before any key is touched.
- **Built for agents.** MCP server, native SDK, and CLI. A wallet created by one tool works in every other.