# Node.js SDK — `@open-wallet-standard/core`

```bash
npm install @open-wallet-standard/core
```

Native NAPI bindings — Rust core runs in-process, no subprocess or server.

## Types

```typescript
interface AccountInfo {
  chainId: string;        // CAIP-2 (e.g. "eip155:1")
  address: string;
  derivationPath: string; // e.g. "m/44'/60'/0'/0/0"
}

interface WalletInfo {
  id: string;             // UUID v4
  name: string;
  accounts: AccountInfo[];
  createdAt: string;      // ISO 8601
}

interface SignResult {
  signature: string;      // Hex-encoded
  recoveryId?: number;    // EVM/Tron only
}

interface SendResult {
  txHash: string;
}
```

## Mnemonic

```javascript
import { generateMnemonic, deriveAddress } from "@open-wallet-standard/core";

const phrase = generateMnemonic(12);       // or 24
const addr = deriveAddress(phrase, "evm"); // any chain: evm, solana, sui, bitcoin, cosmos, tron, ton
```

## Wallet Management

```javascript
import {
  createWallet,
  importWalletMnemonic,
  importWalletPrivateKey,
  listWallets,
  getWallet,
  deleteWallet,
  renameWallet,
  exportWallet,
} from "@open-wallet-standard/core";

// Create
const wallet = createWallet("my-wallet");
// createWallet(name, passphrase?, words?, vaultPath?)

// Import from mnemonic
const w1 = importWalletMnemonic("imported", "goose puzzle ...");
// importWalletMnemonic(name, mnemonic, passphrase?, index?, vaultPath?)

// Import from private key (default: evm/secp256k1)
const w2 = importWalletPrivateKey("from-evm", "4c0883a691...");

// Import Ed25519 key (solana/sui/ton)
const w3 = importWalletPrivateKey("from-sol", "9d61b19d...", undefined, undefined, "solana");

// Import explicit keys for both curves
const w4 = importWalletPrivateKey("both", "", undefined, undefined, undefined, "4c08...", "9d61...");
// importWalletPrivateKey(name, privateKeyHex, passphrase?, vaultPath?, chain?, secp256k1Key?, ed25519Key?)

// List / get / delete / rename / export
const wallets = listWallets();           // listWallets(vaultPath?)
const w = getWallet("my-wallet");        // getWallet(nameOrId, vaultPath?)
deleteWallet("my-wallet");               // deleteWallet(nameOrId, vaultPath?)
renameWallet("old", "new");              // renameWallet(nameOrId, newName, vaultPath?)
const secret = exportWallet("my-wallet"); // exportWallet(nameOrId, passphrase?, vaultPath?)
// Returns mnemonic string or JSON: {"secp256k1":"hex","ed25519":"hex"}
```

## Signing

```javascript
import { signMessage, signTransaction, signAndSend } from "@open-wallet-standard/core";

// Sign message
const sig = signMessage("my-wallet", "evm", "hello world");
// sig.signature => hex string
// sig.recoveryId => 0 or 1 (EVM/Tron only)
// signMessage(wallet, chain, message, passphrase?, encoding?, index?, vaultPath?)

// Sign transaction
const txSig = signTransaction("my-wallet", "evm", "02f8...");
// signTransaction(wallet, chain, txHex, passphrase?, index?, vaultPath?)

// Sign and broadcast
const result = signAndSend("my-wallet", "evm", "02f8...", undefined, undefined, "https://rpc...");
// result.txHash => "0x..."
// signAndSend(wallet, chain, txHex, passphrase?, index?, rpcUrl?, vaultPath?)
```

## Custom Vault Path

Every function accepts an optional `vaultPath` parameter (last argument). Useful for testing:

```javascript
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const vault = mkdtempSync(join(tmpdir(), "ows-"));
const wallet = createWallet("test", undefined, 12, vault);
```
