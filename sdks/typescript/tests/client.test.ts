import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LWSClient } from "../src/client.js";
import { LwsError, LwsErrorCode } from "../src/errors.js";
import type {
  WalletDescriptor,
  SignResult,
  SignAndSendResult,
  SignMessageResult,
  Policy,
  ApiKey,
} from "../src/types.js";
import { readFileSync, existsSync } from "fs";
import { resolve } from "path";

// ---------------------------------------------------------------------------
// fetch mock helpers
// ---------------------------------------------------------------------------

function mockFetch(
  status: number,
  body?: unknown,
): ReturnType<typeof vi.fn> {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as Response);
}

let originalFetch: typeof globalThis.fetch;

beforeEach(() => {
  originalFetch = globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

// ---------------------------------------------------------------------------
// Client tests
// ---------------------------------------------------------------------------

describe("LWSClient", () => {
  describe("unlock", () => {
    it("should unlock and set session token", async () => {
      const mock = mockFetch(200, { session_token: "lws_session_abc" });
      globalThis.fetch = mock;

      const client = new LWSClient();
      const token = await client.unlock("my-passphrase");

      expect(token).toBe("lws_session_abc");
      expect(mock).toHaveBeenCalledOnce();

      const [url, opts] = mock.mock.calls[0];
      expect(url).toBe("http://127.0.0.1:8402/v1/auth/unlock");
      expect(opts.method).toBe("POST");
      expect(JSON.parse(opts.body)).toEqual({ passphrase: "my-passphrase" });
    });

    it("should use session token for subsequent requests", async () => {
      const mock = vi.fn()
        .mockResolvedValueOnce({
          ok: true, status: 200,
          json: () => Promise.resolve({ session_token: "lws_session_xyz" }),
        } as Response)
        .mockResolvedValueOnce({
          ok: true, status: 200,
          json: () => Promise.resolve([]),
        } as Response);
      globalThis.fetch = mock;

      const client = new LWSClient();
      await client.unlock("pass");
      await client.listWallets();

      const [, opts] = mock.mock.calls[1];
      expect(opts.headers["Authorization"]).toBe("Bearer lws_session_xyz");
    });
  });

  describe("wallets", () => {
    it("should list wallets", async () => {
      const wallets: WalletDescriptor[] = [{
        id: "w1", name: "Wallet 1", chains: ["evm"],
        accounts: [], created_at: "2024-01-01T00:00:00Z",
      }];
      globalThis.fetch = mockFetch(200, wallets);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.listWallets();

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("Wallet 1");
    });

    it("should filter by chain type", async () => {
      const mock = mockFetch(200, []);
      globalThis.fetch = mock;

      const client = new LWSClient({ apiKey: "lws_key_test" });
      await client.listWallets("solana");

      const [url] = mock.mock.calls[0];
      expect(url).toContain("chain_type=solana");
    });

    it("should get wallet by id", async () => {
      const wallet: WalletDescriptor = {
        id: "w1", name: "My Wallet", chains: ["evm", "solana"],
        accounts: [{
          chain: "eip155:1", address: "0xabc",
          derivation_path: "m/44'/60'/0'/0/0", account_id: "eip155:1:0xabc",
        }],
        created_at: "2024-01-01T00:00:00Z",
      };
      globalThis.fetch = mockFetch(200, wallet);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.getWallet("w1");

      expect(result.id).toBe("w1");
      expect(result.accounts).toHaveLength(1);
    });

    it("should create wallet", async () => {
      const wallet: WalletDescriptor = {
        id: "w-new", name: "New Wallet", chains: ["evm"],
        accounts: [], created_at: "2024-01-01T00:00:00Z",
      };
      globalThis.fetch = mockFetch(201, wallet);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.createWallet({ name: "New Wallet", chains: ["evm"] });

      expect(result.id).toBe("w-new");
    });
  });

  describe("signing", () => {
    it("should sign transaction", async () => {
      globalThis.fetch = mockFetch(200, { signed_transaction: "0xsigned" });

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.sign({
        wallet_id: "w1", chain: "eip155:1",
        transaction: { to: "0x123", value: "100" },
      });

      expect(result.signed_transaction).toBe("0xsigned");
    });

    it("should sign and send transaction", async () => {
      globalThis.fetch = mockFetch(200, {
        tx_hash: "0xtxhash", status: "confirmed",
      });

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.signAndSend({
        wallet_id: "w1", chain: "eip155:8453",
        transaction: { to: "0x456", value: "200" },
      });

      expect(result.tx_hash).toBe("0xtxhash");
      expect(result.status).toBe("confirmed");
    });

    it("should sign message", async () => {
      globalThis.fetch = mockFetch(200, { signature: "0xsig" });

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.signMessage({
        wallet_id: "w1", chain: "eip155:1",
        message: "hello", encoding: "utf8",
      });

      expect(result.signature).toBe("0xsig");
    });
  });

  describe("policies", () => {
    it("should get policies", async () => {
      globalThis.fetch = mockFetch(200, [
        { id: "p1", name: "limit", executable: "/bin/policy" },
      ]);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const result = await client.getPolicy("w1");

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("limit");
    });
  });

  describe("API keys", () => {
    it("should create api key", async () => {
      globalThis.fetch = mockFetch(201, {
        id: "k1", name: "agent-key", key_hash: "sha256abc",
        scoped_wallets: ["w1"], created_at: "2024-01-01T00:00:00Z",
        key: "lws_key_newkey",
      });

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const key = await client.createApiKey({ name: "agent-key", wallet_ids: ["w1"] });

      expect(key.key).toBe("lws_key_newkey");
    });

    it("should list api keys", async () => {
      globalThis.fetch = mockFetch(200, [{
        id: "k1", name: "key1", key_hash: "h1",
        scoped_wallets: [], created_at: "2024-01-01T00:00:00Z",
      }]);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const keys = await client.listApiKeys();

      expect(keys).toHaveLength(1);
    });

    it("should get api key", async () => {
      globalThis.fetch = mockFetch(200, {
        id: "k1", name: "key1", key_hash: "h1",
        scoped_wallets: [], created_at: "2024-01-01T00:00:00Z",
      });

      const client = new LWSClient({ apiKey: "lws_key_test" });
      const key = await client.getApiKey("k1");

      expect(key.id).toBe("k1");
    });

    it("should revoke api key", async () => {
      globalThis.fetch = mockFetch(204);

      const client = new LWSClient({ apiKey: "lws_key_test" });
      await client.revokeApiKey("k1");
    });
  });

  describe("error handling", () => {
    it("should throw LwsError on 404", async () => {
      globalThis.fetch = mockFetch(404, {
        code: "WALLET_NOT_FOUND",
        message: "wallet not found: missing",
      });

      const client = new LWSClient({ apiKey: "lws_key_test" });

      await expect(client.getWallet("missing")).rejects.toThrow(LwsError);

      try {
        await client.getWallet("missing");
      } catch (e) {
        const err = e as LwsError;
        expect(err.code).toBe(LwsErrorCode.WALLET_NOT_FOUND);
        expect(err.message).toBe("wallet not found: missing");
        expect(err.statusCode).toBe(404);
      }
    });

    it("should throw LwsError on policy denied", async () => {
      globalThis.fetch = mockFetch(403, {
        code: "POLICY_DENIED",
        message: "policy denied: exceeds spending limit",
      });

      const client = new LWSClient({ apiKey: "lws_key_test" });

      try {
        await client.sign({
          wallet_id: "w1", chain: "eip155:1",
          transaction: { to: "0x123" },
        });
        expect.fail("should have thrown");
      } catch (e) {
        const err = e as LwsError;
        expect(err.code).toBe(LwsErrorCode.POLICY_DENIED);
      }
    });
  });

  describe("auth header", () => {
    it("should include api key in Authorization header", async () => {
      const mock = mockFetch(200, []);
      globalThis.fetch = mock;

      const client = new LWSClient({ apiKey: "lws_key_test" });
      await client.listWallets();

      const [, opts] = mock.mock.calls[0];
      expect(opts.headers["Authorization"]).toBe("Bearer lws_key_test");
    });

    it("should not include Authorization when no key", async () => {
      const mock = mockFetch(200, []);
      globalThis.fetch = mock;

      const client = new LWSClient();
      await client.listWallets();

      const [, opts] = mock.mock.calls[0];
      expect(opts.headers["Authorization"]).toBeUndefined();
    });
  });

  describe("custom base URL", () => {
    it("should use custom base URL", async () => {
      const mock = mockFetch(200, []);
      globalThis.fetch = mock;

      const client = new LWSClient({ baseUrl: "http://localhost:9999" });
      await client.listWallets();

      const [url] = mock.mock.calls[0];
      expect((url as string).startsWith("http://localhost:9999/v1/wallets")).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// Drift detection: ensure SDK types stay in sync with lws-core Rust source
// ---------------------------------------------------------------------------

const CORE_ROOT = resolve(__dirname, "../../../lws/crates/lws-core/src");

function readRustFile(name: string): string {
  const path = resolve(CORE_ROOT, name);
  if (!existsSync(path)) return "";
  return readFileSync(path, "utf-8");
}

function extractEnumVariants(src: string, enumName: string): string[] {
  const match = src.match(new RegExp(`enum ${enumName} \\{([^}]+)\\}`));
  if (!match) return [];
  return [...match[1].matchAll(/(\w+)/g)].map((m) => m[1]);
}

function pascalToScreamingSnake(s: string): string {
  return s.replace(/(?<!^)(?=[A-Z])/g, "_").toUpperCase();
}

function pascalToSnake(s: string): string {
  return s.replace(/(?<!^)(?=[A-Z])/g, "_").toLowerCase();
}

function extractStructFields(src: string, structName: string): string[] {
  const match = src.match(
    new RegExp(`struct ${structName} \\{([^}]+)\\}`),
  );
  if (!match) return [];
  return [...match[1].matchAll(/pub (\w+):/g)].map((m) => m[1]);
}

describe("Drift detection", () => {
  describe("enum values", () => {
    it("ChainType matches Rust", () => {
      const src = readRustFile("chain.rs");
      if (!src) return;
      const variants = extractEnumVariants(src, "ChainType");
      const rustValues = variants.map((v) => v.toLowerCase());
      const sdkValues: string[] = ["evm", "solana", "cosmos", "bitcoin", "tron"];
      expect(sdkValues).toEqual(rustValues);
    });

    it("LwsErrorCode matches Rust", () => {
      const src = readRustFile("error.rs");
      if (!src) return;
      const variants = extractEnumVariants(src, "LwsErrorCode");
      const rustCodes = new Set(variants.map(pascalToScreamingSnake));
      const sdkCodes = new Set(Object.values(LwsErrorCode));
      expect(sdkCodes).toEqual(rustCodes);
    });

    it("MessageEncoding matches Rust", () => {
      const src = readRustFile("types.rs");
      if (!src) return;
      const variants = extractEnumVariants(src, "MessageEncoding");
      const rustValues = variants.map((v) => v.toLowerCase());
      const sdkValues: string[] = ["utf8", "hex", "base64"];
      expect(sdkValues).toEqual(rustValues);
    });

    it("TransactionStatus matches Rust", () => {
      const src = readRustFile("types.rs");
      if (!src) return;
      const variants = extractEnumVariants(src, "TransactionStatus");
      const rustValues = variants.map((v) => v.toLowerCase());
      const sdkValues: string[] = ["pending", "confirmed", "failed"];
      expect(sdkValues).toEqual(rustValues);
    });

    it("StateChangeType matches Rust", () => {
      const src = readRustFile("types.rs");
      if (!src) return;
      const variants = extractEnumVariants(src, "StateChangeType");
      const rustValues = variants.map(pascalToSnake);
      const sdkValues: string[] = [
        "balance_change", "token_transfer", "approval", "contract_call",
      ];
      expect(sdkValues).toEqual(rustValues);
    });
  });

  describe("struct fields", () => {
    const typesRs = readRustFile("types.rs");

    const structTests: Array<{
      name: string;
      sdkFields: string[];
      extraSdkFields?: string[];
    }> = [
      {
        name: "WalletDescriptor",
        sdkFields: ["id", "name", "chains", "accounts", "created_at", "updated_at"],
      },
      {
        name: "AccountDescriptor",
        sdkFields: ["chain", "address", "derivation_path", "account_id"],
      },
      {
        name: "SignResult",
        sdkFields: ["signed_transaction", "simulation"],
      },
      {
        name: "SignAndSendResult",
        sdkFields: ["tx_hash", "status", "simulation"],
      },
      {
        name: "SimulationResult",
        sdkFields: ["success", "state_changes", "gas_estimate", "error"],
      },
      {
        name: "StateChange",
        sdkFields: ["change_type", "address", "amount", "token"],
      },
      {
        name: "Policy",
        sdkFields: ["id", "name", "executable", "timeout_ms"],
      },
      {
        name: "ApiKey",
        sdkFields: ["id", "name", "key_hash", "scoped_wallets", "created_at", "expires_at", "key"],
        extraSdkFields: ["key"], // SDK-only: raw key returned at creation
      },
    ];

    for (const { name, sdkFields, extraSdkFields } of structTests) {
      it(`${name} fields match Rust`, () => {
        if (!typesRs) return;
        const rustFields = new Set(extractStructFields(typesRs, name));
        const sdkFieldSet = new Set(sdkFields);
        const extra = new Set(extraSdkFields ?? []);

        // All Rust fields must be in SDK
        for (const f of rustFields) {
          expect(sdkFieldSet.has(f)).toBe(true);
        }
        // All SDK fields must be in Rust (minus known extras)
        for (const f of sdkFieldSet) {
          if (!extra.has(f)) {
            expect(rustFields.has(f)).toBe(true);
          }
        }
      });
    }
  });

  it("REST endpoints match spec", () => {
    const specPath = resolve(__dirname, "../../../docs/06-agent-access-layer.md");
    if (!existsSync(specPath)) return;
    const spec = readFileSync(specPath, "utf-8");

    const endpoints = [
      "POST /v1/wallets",
      "GET  /v1/wallets",
      "GET  /v1/wallets/:id",
      "POST /v1/wallets/:id/sign",
      "POST /v1/wallets/:id/sign-and-send",
      "POST /v1/wallets/:id/sign-message",
      "GET  /v1/wallets/:id/policy",
      "POST   /v1/keys",
      "GET    /v1/keys",
      "GET    /v1/keys/:id",
      "DELETE /v1/keys/:id",
    ];

    for (const endpoint of endpoints) {
      const normalized = endpoint.replace(/\s+/g, "\\s+");
      expect(spec).toMatch(new RegExp(normalized));
    }
  });
});
