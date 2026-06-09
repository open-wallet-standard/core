const COLLECTIONS = new Set(["keys", "policies", "wallets"]);

function assertCollection(kind) {
  if (!COLLECTIONS.has(kind)) {
    throw new Error(`unknown OWS collection: ${kind}`);
  }
}

export class MemoryOwsStore {
  #collections = new Map();

  async ensureCollection(kind) {
    assertCollection(kind);
    if (!this.#collections.has(kind)) {
      this.#collections.set(kind, new Map());
    }
  }

  async list(kind) {
    await this.ensureCollection(kind);
    return [...this.#collections.get(kind).keys()].sort();
  }

  async read(kind, id) {
    await this.ensureCollection(kind);
    return this.#collections.get(kind).get(id) ?? null;
  }

  async remove(kind, id) {
    await this.ensureCollection(kind);
    this.#collections.get(kind).delete(id);
  }

  async write(kind, id, json) {
    await this.ensureCollection(kind);
    this.#collections.get(kind).set(id, json);
  }
}
