# Node.js SDK

> Native bindings for Node.js via NAPI. No CLI, no server, no subprocess.

[![npm](https://img.shields.io/npm/v/@open-wallet-standard/core)](https://www.npmjs.com/package/@open-wallet-standard/core)

## Install

```bash
npm install @open-wallet-standard/core
```

Wallet metadata is stored under `~/.ows/wallets/`. Mnemonics and private keys are stored in the OS keyring.

## Quick Start

```javascript
import {
  createWallet,
  listWallets,
  signMessage,
  exportWallet,
} from "@open-wallet-standard/core";

const wallet = createWallet("my-wallet");
console.log(wallet.accounts.length); // 7

const wallets = listWallets();
const sig = signMessage("my-wallet", "evm", "hello");
const phrase = exportWallet("my-wallet");

console.log(wallets.length);
console.log(sig.signature);
console.log(phrase.split(" ").length);
```

## Types

```typescript
interface AccountInfo {
  chainId: string;
  address: string;
  derivationPath: string;
}

interface WalletInfo {
  id: string;
  name: string;
  accounts: AccountInfo[];
  createdAt: string;
}

interface SignResult {
  signature: string;
  recoveryId?: number;
}

interface SendResult {
  txHash: string;
}
```

## API

### Mnemonics

#### `generateMnemonic(words?)`

Generate a new 12- or 24-word BIP-39 mnemonic.

#### `deriveAddress(mnemonic, chain, index?)`

Derive an address from a mnemonic without creating a wallet.

### Wallet Management

#### `createWallet(name, words?, vaultPath?)`

Create a wallet, derive accounts for all supported chain families, store the secret in the OS keyring, and write wallet metadata to the vault.

#### `importWalletMnemonic(name, mnemonic, index?, vaultPath?)`

Import a mnemonic-backed wallet.

#### `importWalletPrivateKey(name, privateKeyHex, chain?, vaultPath?, secp256k1Key?, ed25519Key?)`

Import a private-key wallet. When only one curve key is provided, OWS generates the other curve's key so the wallet still has all 7 chain accounts.

#### `listWallets(vaultPath?)`

List wallet metadata from the vault.

#### `getWallet(nameOrId, vaultPath?)`

Load one wallet by name or ID.

#### `renameWallet(nameOrId, newName, vaultPath?)`

Rename a wallet. The keyring entry stays stable because it is keyed by wallet ID.

#### `deleteWallet(nameOrId, vaultPath?)`

Delete the metadata file and the matching keyring entry.

#### `exportWallet(nameOrId, vaultPath?)`

Export the wallet secret.

- Mnemonic wallets return the phrase string.
- Private-key wallets return JSON with `secp256k1` and `ed25519` fields.

### Signing

#### `signMessage(wallet, chain, message, encoding?, index?, vaultPath?)`

Sign a message with chain-specific formatting.

#### `signTypedData(wallet, chain, typedDataJson, index?, vaultPath?)`

Sign EIP-712 typed data for EVM chains.

#### `signTransaction(wallet, chain, txHex, index?, vaultPath?)`

Sign a raw transaction.

#### `signAndSend(wallet, chain, txHex, index?, rpcUrl?, vaultPath?)`

Sign and broadcast a transaction.

## Examples

### Import from mnemonic

```javascript
import { importWalletMnemonic } from "@open-wallet-standard/core";

const wallet = importWalletMnemonic(
  "imported",
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
);

console.log(wallet.accounts.length); // 7
```

### Import explicit curve keys

```javascript
import { importWalletPrivateKey } from "@open-wallet-standard/core";

const wallet = importWalletPrivateKey(
  "both-keys",
  "",
  undefined,
  undefined,
  "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
);

console.log(wallet.accounts.length); // 7
```

### Custom vault root

```javascript
import { createWallet } from "@open-wallet-standard/core";

const wallet = createWallet("isolated", 12, "/tmp/ows-test");
console.log(wallet.id);
```

`vaultPath` points at the vault root, not the `wallets/` subdirectory. When omitted, OWS uses `~/.ows/`.
