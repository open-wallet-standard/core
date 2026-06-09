import * as wasm from "../pkg/ows_web.js";
import { IndexedDbOwsStore } from "./stores/indexeddb.js";

const COLLECTIONS = ["keys", "policies", "wallets"];
const HEX = "0123456789abcdef";

export { IndexedDbOwsStore } from "./stores/indexeddb.js";
export { LightningFsOwsStore } from "./stores/lightning-fs.js";
export { MemoryOwsStore } from "./stores/memory.js";

export class OwsWebError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = "OwsWebError";
  }

  static from(error) {
    const raw = typeof error === "string" ? error : error?.message ?? String(error);
    try {
      const parsed = JSON.parse(raw);
      if (parsed?.code && parsed?.message) {
        return new OwsWebError(parsed.code, parsed.message);
      }
    } catch {
      // Fall through to the generic wrapper below.
    }
    return new OwsWebError("UNKNOWN", raw);
  }
}

function ensureCrypto() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new OwsWebError("UNSUPPORTED_BROWSER_FEATURE", "crypto.getRandomValues is required");
  }
  return globalThis.crypto;
}

function nowIso() {
  return new Date().toISOString();
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  ensureCrypto().getRandomValues(bytes);
  return bytes;
}

function randomHex(length) {
  let out = "";
  for (const byte of randomBytes(length)) {
    out += HEX[byte >> 4] + HEX[byte & 15];
  }
  return out;
}

function randomToken() {
  return `ows_key_${randomHex(32)}`;
}

function randomUuid() {
  const crypto = ensureCrypto();
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }

  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => HEX[byte >> 4] + HEX[byte & 15]);
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}

function stringify(value) {
  return JSON.stringify(value);
}

function unsupported(name) {
  throw new OwsWebError("UNSUPPORTED_BROWSER_FEATURE", `${name} is not supported in browser`);
}

function wasmJson(call) {
  try {
    return JSON.parse(call());
  } catch (error) {
    throw OwsWebError.from(error);
  }
}

function wasmString(call) {
  try {
    return call();
  } catch (error) {
    throw OwsWebError.from(error);
  }
}

export async function createOwsWeb({ store } = {}) {
  const resolvedStore = store ?? new IndexedDbOwsStore();
  for (const kind of COLLECTIONS) {
    await resolvedStore.ensureCollection(kind);
  }
  return new OwsWeb(resolvedStore);
}

export class OwsWeb {
  constructor(store) {
    this.store = store;
  }

  async #collection(kind) {
    await this.store.ensureCollection(kind);
    const ids = await this.store.list(kind);
    const values = [];
    for (const id of ids.sort()) {
      const json = await this.store.read(kind, id);
      if (json) {
        values.push(JSON.parse(json));
      }
    }
    return stringify(values);
  }

  async #keys() {
    return this.#collection("keys");
  }

  async #policies() {
    return this.#collection("policies");
  }

  async #wallets() {
    return this.#collection("wallets");
  }

  async #write(kind, artifact) {
    await this.store.write(kind, artifact.id, stringify(artifact));
  }

  deriveAddress(mnemonic, chain, index = 0) {
    return wasmString(() => wasm.deriveAddress(mnemonic, chain, index));
  }

  generateMnemonic(words = 12) {
    return wasmString(() => wasm.generateMnemonic(words));
  }

  async createApiKey(name, walletIds, policyIds, passphrase, expiresAt) {
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    const result = wasmJson(() =>
      wasm.createApiKey(
        name,
        stringify(walletIds),
        stringify(policyIds),
        passphrase ?? "",
        expiresAt ?? "",
        randomToken(),
        randomUuid(),
        nowIso(),
        wallets,
        policies,
      ),
    );
    await this.#write("keys", result.key);
    return {
      id: result.id,
      name: result.name,
      token: result.token,
    };
  }

  async createPolicy(policy) {
    const policyJson = typeof policy === "string" ? policy : stringify(policy);
    const created = wasmJson(() => wasm.createPolicy(policyJson));
    await this.#write("policies", created);
    return created;
  }

  async createWallet(name, passphrase, words = 12) {
    const wallets = await this.#wallets();
    const result = wasmJson(() =>
      wasm.createWallet(name, passphrase ?? "", words, wallets, randomUuid(), nowIso()),
    );
    await this.#write("wallets", result.wallet);
    return result.info;
  }

  async deletePolicy(id) {
    const policies = await this.#policies();
    const result = wasmJson(() => wasm.deletePolicy(id, policies));
    await this.store.remove("policies", result.id);
  }

  async deleteWallet(nameOrId) {
    const wallets = await this.#wallets();
    const result = wasmJson(() => wasm.deleteWallet(nameOrId, wallets));
    await this.store.remove("wallets", result.id);
  }

  async exportWallet(nameOrId, passphrase) {
    const wallets = await this.#wallets();
    return wasmString(() => wasm.exportWallet(nameOrId, passphrase ?? "", wallets));
  }

  async getPolicy(id) {
    const policies = await this.#policies();
    return wasmJson(() => wasm.getPolicy(id, policies));
  }

  async getWallet(nameOrId) {
    const wallets = await this.#wallets();
    return wasmJson(() => wasm.getWallet(nameOrId, wallets));
  }

  async importWalletMnemonic(name, mnemonic, passphrase, index = 0) {
    const wallets = await this.#wallets();
    const result = wasmJson(() =>
      wasm.importWalletMnemonic(
        name,
        mnemonic,
        passphrase ?? "",
        index,
        wallets,
        randomUuid(),
        nowIso(),
      ),
    );
    await this.#write("wallets", result.wallet);
    return result.info;
  }

  async importWalletPrivateKey(
    name,
    privateKeyHex,
    passphrase,
    chain,
    secp256k1Key,
    ed25519Key,
  ) {
    const wallets = await this.#wallets();
    const result = wasmJson(() =>
      wasm.importWalletPrivateKey(
        name,
        privateKeyHex,
        passphrase ?? "",
        chain ?? "",
        secp256k1Key ?? "",
        ed25519Key ?? "",
        wallets,
        randomUuid(),
        nowIso(),
      ),
    );
    await this.#write("wallets", result.wallet);
    return result.info;
  }

  async listApiKeys() {
    const keys = await this.#keys();
    return wasmJson(() => wasm.listApiKeys(keys));
  }

  async listPolicies() {
    const policies = await this.#policies();
    return wasmJson(() => wasm.listPolicies(policies));
  }

  async listWallets() {
    const wallets = await this.#wallets();
    return wasmJson(() => wasm.listWallets(wallets));
  }

  async renameWallet(nameOrId, newName) {
    const wallets = await this.#wallets();
    const result = wasmJson(() => wasm.renameWallet(nameOrId, newName, wallets));
    await this.#write("wallets", result.wallet);
    return result.info;
  }

  async revokeApiKey(id) {
    const keys = await this.#keys();
    const result = wasmJson(() => wasm.revokeApiKey(id, keys));
    await this.store.remove("keys", result.id);
  }

  async signAndSend() {
    unsupported("signAndSend");
  }

  async signAuthorization(wallet, chain, address, nonce, passphrase, index = 0) {
    const keys = await this.#keys();
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    return wasmJson(() =>
      wasm.signAuthorization(
        wallet,
        chain,
        address,
        nonce,
        passphrase ?? "",
        index,
        nowIso(),
        wallets,
        keys,
        policies,
      ),
    );
  }

  async signHash(wallet, chain, hashHex, passphrase, index = 0) {
    const keys = await this.#keys();
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    return wasmJson(() =>
      wasm.signHash(
        wallet,
        chain,
        hashHex,
        passphrase ?? "",
        index,
        nowIso(),
        wallets,
        keys,
        policies,
      ),
    );
  }

  async signMessage(wallet, chain, message, passphrase, encoding = "utf8", index = 0) {
    const keys = await this.#keys();
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    return wasmJson(() =>
      wasm.signMessage(
        wallet,
        chain,
        message,
        passphrase ?? "",
        encoding,
        index,
        nowIso(),
        wallets,
        keys,
        policies,
      ),
    );
  }

  async signTransaction(wallet, chain, txHex, passphrase, index = 0) {
    const keys = await this.#keys();
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    return wasmJson(() =>
      wasm.signTransaction(
        wallet,
        chain,
        txHex,
        passphrase ?? "",
        index,
        nowIso(),
        wallets,
        keys,
        policies,
      ),
    );
  }

  async signTypedData(wallet, chain, typedDataJson, passphrase, index = 0) {
    const payload = typeof typedDataJson === "string" ? typedDataJson : stringify(typedDataJson);
    const keys = await this.#keys();
    const policies = await this.#policies();
    const wallets = await this.#wallets();
    return wasmJson(() =>
      wasm.signTypedData(
        wallet,
        chain,
        payload,
        passphrase ?? "",
        index,
        nowIso(),
        wallets,
        keys,
        policies,
      ),
    );
  }
}
