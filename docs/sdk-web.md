# Browser WASM SDK

> Browser package for local OWS wallet storage, signing, and declarative policy enforcement.

This document is non-normative reference implementation documentation. Package names and function signatures here do not define the OWS standard.

## Install

```bash
npm install @open-wallet-standard/web
```

## Quick Start

```javascript
import { createOwsWeb, IndexedDbOwsStore } from "@open-wallet-standard/web";

const ows = await createOwsWeb({
  store: new IndexedDbOwsStore(),
});

const wallet = await ows.createWallet("agent-treasury");
const sig = await ows.signMessage(wallet.id, "evm", "hello");

console.log(sig.signature);
```

## Storage

The browser SDK stores the same wallet, API-key, and policy JSON artifacts as the native SDK. Instead of taking a `vaultPath`, it takes an async store:

```typescript
interface OwsWebStore {
  ensureCollection(kind: "keys" | "policies" | "wallets"): Promise<void>;
  list(kind: "keys" | "policies" | "wallets"): Promise<string[]>;
  read(kind: "keys" | "policies" | "wallets", id: string): Promise<string | null>;
  remove(kind: "keys" | "policies" | "wallets", id: string): Promise<void>;
  write(kind: "keys" | "policies" | "wallets", id: string, json: string): Promise<void>;
}
```

Included adapters:

- `IndexedDbOwsStore`
- `LightningFsOwsStore`
- `MemoryOwsStore`

## Browser Profile

The browser SDK targets `Storage + Signing + Policy (declarative)`.

Supported operations:

- API key creation, listing, and revocation
- Mnemonic generation and address derivation
- Policy creation, listing, lookup, and deletion for declarative policies
- Wallet creation, import, export, lookup, listing, rename, and deletion
- `signAuthorization`, `signHash`, `signMessage`, `signTransaction`, and `signTypedData`

Unavailable host-only operations:

- CLI vault migration
- `signAndSend`
- executable policies
- filesystem permission checks
- local audit log appenders
- OS process and memory hardening
