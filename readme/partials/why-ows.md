## Why OWS

- **Local key custody.** Private keys stay encrypted at rest and are decrypted only inside the OWS signing path after the relevant checks pass. Current implementations harden in-process memory handling and wipe key material after use.
- **Every chain, one interface.** EVM, Solana, XRPL, Sui, Bitcoin, Cosmos, Tron, TON, Spark, Filecoin — all first-class. CAIP-2/CAIP-10 addressing abstracts away chain-specific details.
- **Policy before signing.** A pre-signing policy engine gates agent (API key) operations before decryption — chain allowlists, expiry, and optional custom executables.
- **Built for agents.** Native SDK and CLI today. A wallet created by one tool works in every other.