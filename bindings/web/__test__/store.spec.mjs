import assert from "node:assert/strict";
import test from "node:test";

import { LightningFsOwsStore } from "../src/stores/lightning-fs.js";
import { MemoryOwsStore } from "../src/stores/memory.js";

class FakeFs {
  constructor() {
    this.dirs = new Set(["/"]);
    this.files = new Map();
  }

  async mkdir(path) {
    if (this.dirs.has(path)) {
      const error = new Error("already exists");
      error.code = "EEXIST";
      throw error;
    }
    this.dirs.add(path);
  }

  async readdir(path) {
    if (!this.dirs.has(path)) {
      const error = new Error("not found");
      error.code = "ENOENT";
      throw error;
    }
    const prefix = `${path}/`;
    return [...this.files.keys()]
      .filter((file) => file.startsWith(prefix))
      .map((file) => file.slice(prefix.length))
      .sort();
  }

  async readFile(path) {
    if (!this.files.has(path)) {
      const error = new Error("not found");
      error.code = "ENOENT";
      throw error;
    }
    return this.files.get(path);
  }

  async unlink(path) {
    this.files.delete(path);
  }

  async writeFile(path, contents) {
    this.files.set(path, contents);
  }
}

test("MemoryOwsStore stores collections independently", async () => {
  const store = new MemoryOwsStore();

  await store.write("wallets", "b", "{\"id\":\"b\"}");
  await store.write("wallets", "a", "{\"id\":\"a\"}");
  await store.write("keys", "a", "{\"id\":\"key\"}");

  assert.deepEqual(await store.list("wallets"), ["a", "b"]);
  assert.equal(await store.read("wallets", "a"), "{\"id\":\"a\"}");
  assert.equal(await store.read("keys", "a"), "{\"id\":\"key\"}");

  await store.remove("wallets", "a");
  assert.deepEqual(await store.list("wallets"), ["b"]);
});

test("LightningFsOwsStore maps artifacts to JSON files", async () => {
  const fs = new FakeFs();
  const store = new LightningFsOwsStore(fs, { root: "/vault" });

  await store.write("policies", "base-only", "{\"id\":\"base-only\"}");

  assert.deepEqual(await store.list("policies"), ["base-only"]);
  assert.equal(await store.read("policies", "base-only"), "{\"id\":\"base-only\"}");

  await store.remove("policies", "base-only");
  assert.equal(await store.read("policies", "base-only"), null);
});
