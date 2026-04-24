const COLLECTIONS = new Set(["keys", "policies", "wallets"]);
const STORE = "artifacts";

function assertCollection(kind) {
  if (!COLLECTIONS.has(kind)) {
    throw new Error(`unknown OWS collection: ${kind}`);
  }
}

function keyFor(kind, id) {
  return `${kind}:${id}`;
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
  });
}

export class IndexedDbOwsStore {
  constructor({ name = "ows-web-vault", version = 1 } = {}) {
    this.name = name;
    this.version = version;
    this.dbPromise = null;
  }

  async #db() {
    if (this.dbPromise) {
      return this.dbPromise;
    }
    if (!globalThis.indexedDB) {
      throw new Error("IndexedDB is not available in this environment");
    }

    this.dbPromise = new Promise((resolve, reject) => {
      const request = globalThis.indexedDB.open(this.name, this.version);
      request.onerror = () => reject(request.error);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE)) {
          const store = db.createObjectStore(STORE, { keyPath: "key" });
          store.createIndex("kind", "kind", { unique: false });
        }
      };
      request.onsuccess = () => resolve(request.result);
    });

    return this.dbPromise;
  }

  async #objectStore(mode) {
    const db = await this.#db();
    return db.transaction(STORE, mode).objectStore(STORE);
  }

  async ensureCollection(kind) {
    assertCollection(kind);
    await this.#db();
  }

  async list(kind) {
    await this.ensureCollection(kind);
    const store = await this.#objectStore("readonly");
    const index = store.index("kind");
    const ids = [];

    await new Promise((resolve, reject) => {
      const request = index.openCursor(globalThis.IDBKeyRange.only(kind));
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) {
          resolve();
          return;
        }
        ids.push(cursor.value.id);
        cursor.continue();
      };
    });

    return ids.sort();
  }

  async read(kind, id) {
    await this.ensureCollection(kind);
    const store = await this.#objectStore("readonly");
    const record = await requestToPromise(store.get(keyFor(kind, id)));
    return record?.json ?? null;
  }

  async remove(kind, id) {
    await this.ensureCollection(kind);
    const store = await this.#objectStore("readwrite");
    await requestToPromise(store.delete(keyFor(kind, id)));
  }

  async write(kind, id, json) {
    await this.ensureCollection(kind);
    const store = await this.#objectStore("readwrite");
    await requestToPromise(
      store.put({
        id,
        json,
        key: keyFor(kind, id),
        kind,
      }),
    );
  }
}
