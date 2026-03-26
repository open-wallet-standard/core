# @open-wallet-standard/viem

Viem account adapter for the [Open Wallet Standard](https://openwallet.sh). Creates a viem `Account` backed by an OWS encrypted vault — all signing is delegated to OWS, the key never leaves the vault.

## Install

```bash
npm install @open-wallet-standard/viem viem
```

## Usage

```typescript
import { owsToViemAccount } from "@open-wallet-standard/viem";
import { createWalletClient, http } from "viem";
import { base } from "viem/chains";

const account = owsToViemAccount("my-wallet");

const client = createWalletClient({
  account,
  chain: base,
  transport: http(),
});
```

Works with any viem-based project: mppx, wagmi, x402, etc.

## License

MIT
