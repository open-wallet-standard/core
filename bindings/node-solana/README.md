# @open-wallet-standard/solana

Solana Keypair adapter for the [Open Wallet Standard](https://openwallet.sh). Creates a `@solana/web3.js` `Keypair` from an OWS encrypted vault.

## Install

```bash
npm install @open-wallet-standard/solana @solana/web3.js
```

## Usage

```typescript
import { owsToSolanaKeypair } from "@open-wallet-standard/solana";
import { Connection, Transaction } from "@solana/web3.js";

const keypair = owsToSolanaKeypair("my-wallet");

const connection = new Connection("https://api.mainnet-beta.solana.com");
const tx = new Transaction().add(/* ... */);
tx.sign(keypair);
```

Works with any Solana project: Anchor, spl-token, Metaplex, Solana Agent Kit, etc.

## License

MIT
