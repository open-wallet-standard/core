const COLLECTIONS = new Set(["keys", "policies", "wallets"]);

function assertCollection(kind) {
  if (!COLLECTIONS.has(kind)) {
    throw new Error(`unknown OWS collection: ${kind}`);
  }
}

function fileName(id) {
  return `${id}.json`;
}

function isMissing(error) {
  return error?.code === "ENOENT" || error?.message?.includes("ENOENT");
}

function trimSlashes(path) {
  return path.replace(/^\/+|\/+$/g, "");
}

export class LightningFsOwsStore {
  constructor(fs, { root = "/ows" } = {}) {
    if (!fs) {
      throw new Error("LightningFsOwsStore requires a filesystem instance");
    }
    this.fs = fs.promises ?? fs;
    this.root = `/${trimSlashes(root)}`;
  }

  async #mkdirp(path) {
    const parts = trimSlashes(path).split("/");
    let current = "";
    for (const part of parts) {
      current = `${current}/${part}`;
      try {
        await this.fs.mkdir(current);
      } catch (error) {
        if (!isMissing(error) && error?.code !== "EEXIST") {
          throw error;
        }
      }
    }
  }

  #dir(kind) {
    return `${this.root}/${kind}`;
  }

  #path(kind, id) {
    return `${this.#dir(kind)}/${fileName(id)}`;
  }

  async ensureCollection(kind) {
    assertCollection(kind);
    await this.#mkdirp(this.#dir(kind));
  }

  async list(kind) {
    await this.ensureCollection(kind);
    try {
      const entries = await this.fs.readdir(this.#dir(kind));
      return entries
        .filter((entry) => entry.endsWith(".json"))
        .map((entry) => entry.slice(0, -".json".length))
        .sort();
    } catch (error) {
      if (isMissing(error)) {
        return [];
      }
      throw error;
    }
  }

  async read(kind, id) {
    await this.ensureCollection(kind);
    try {
      return await this.fs.readFile(this.#path(kind, id), "utf8");
    } catch (error) {
      if (isMissing(error)) {
        return null;
      }
      throw error;
    }
  }

  async remove(kind, id) {
    await this.ensureCollection(kind);
    try {
      await this.fs.unlink(this.#path(kind, id));
    } catch (error) {
      if (!isMissing(error)) {
        throw error;
      }
    }
  }

  async write(kind, id, json) {
    await this.ensureCollection(kind);
    await this.fs.writeFile(this.#path(kind, id), json, "utf8");
  }
}
