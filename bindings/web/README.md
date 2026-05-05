# @open-wallet-standard/web

Browser WASM bindings for OWS storage, wallet lifecycle, local signing, and declarative policy checks.

## Install

```bash
npm install @open-wallet-standard/web
```

## Usage

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

The browser package keeps the same wallet, API-key, and policy JSON artifact formats as the native SDK. Storage is provided by an async store interface:

```typescript
interface OwsWebStore {
  ensureCollection(kind: "keys" | "policies" | "wallets"): Promise<void>;
  list(kind: "keys" | "policies" | "wallets"): Promise<string[]>;
  read(kind: "keys" | "policies" | "wallets", id: string): Promise<string | null>;
  remove(kind: "keys" | "policies" | "wallets", id: string): Promise<void>;
  write(kind: "keys" | "policies" | "wallets", id: string, json: string): Promise<void>;
}
```

Adapters are included for IndexedDB, LightningFS-style filesystems, and memory-backed tests.

## Browser Profile

This package targets `Storage + Signing + Policy (declarative)`.

Host-only features are intentionally unavailable in the browser build:

- `signAndSend`
- CLI vault migration
- executable policies
- filesystem permission checks
- local audit log appenders
- OS process and memory hardening
