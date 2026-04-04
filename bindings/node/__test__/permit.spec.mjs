import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { signPermit } from "../src/evm/permit.mjs";

// ---------------------------------------------------------------------------
// Mock helpers
// ---------------------------------------------------------------------------

function encodeString(value) {
  const bytes = Buffer.from(value, "utf8");
  const offset = "0000000000000000000000000000000000000000000000000000000000000020";
  const length = bytes.length.toString(16).padStart(64, "0");
  const data   = bytes.toString("hex").padEnd(Math.ceil(bytes.length / 32) * 64, "0");
  return "0x" + offset + length + data;
}

function encodeUint256(value) {
  return "0x" + BigInt(value).toString(16).padStart(64, "0");
}

function makeMockFetch({ name = "USD Coin", nonce = 0n, eip712Domain = null, revertDomain = false } = {}) {
  return async (_url, init) => {
    const body = JSON.parse(init.body);
    if (body.method === "eth_chainId") {
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x2105" }));
    }
    if (body.method === "eth_call") {
      const selector = body.params[0].data.slice(0, 10);

      if (selector === "0x84b0196e") {
        if (revertDomain) {
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: "execution reverted" } }));
        }
        if (eip712Domain) {
          const nameBytes    = Buffer.from(eip712Domain.name, "utf8");
          const versionBytes = Buffer.from(eip712Domain.version, "utf8");
          const words = [
            "0f00000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000000000000000000000000000000000e0",
            "0000000000000000000000000000000000000000000000000000000000000120",
            eip712Domain.chainId.toString(16).padStart(64, "0"),
            "000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000160",
            nameBytes.length.toString(16).padStart(64, "0"),
            nameBytes.toString("hex").padEnd(64, "0"),
            versionBytes.length.toString(16).padStart(64, "0"),
            versionBytes.toString("hex").padEnd(64, "0"),
            "0000000000000000000000000000000000000000000000000000000000000000",
          ];
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" + words.join("") }));
        }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { message: "execution reverted" } }));
      }

      if (selector === "0x06fdde03") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: encodeString(name) }));
      }

      if (selector === "0x7ecebe00") {
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: encodeUint256(nonce) }));
      }
    }
    throw new Error("Unexpected: " + body.method);
  };
}

const MOCK_SIG = "0x" + "a".repeat(64) + "b".repeat(64) + "1b";
const mockSignTypedData = async (_json) => MOCK_SIG;

const BASE_USDC  = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const SPENDER    = "0xDeadBeefDeadBeefDeadBeefDeadBeefDeadBeef";
const OWNER      = "0x1111111111111111111111111111111111111111";
const BASE_CHAIN = "eip155:8453";
const BASE_PARAMS = {
  token:    BASE_USDC,
  spender:  SPENDER,
  value:    "1000000",
  deadline: 1_800_000_000,
  nonce:    0,
  rpcUrl:   "http://mock-rpc",
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("signPermit", () => {

  it("returns correct v / r / s from mock signature", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 } });
    const result = await signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData);
    assert.equal(result.v, 27);
    assert.equal(result.r, "0x" + "a".repeat(64));
    assert.equal(result.s, "0x" + "b".repeat(64));
    assert.equal(result.signature, MOCK_SIG);
  });

  it("builds correct EIP-712 typed data structure", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 } });
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData);
    assert.equal(typedData.primaryType, "Permit");
    assert.equal(typedData.message.spender, SPENDER);
    assert.equal(typedData.message.value, "1000000");
    assert.equal(typedData.message.deadline, 1_800_000_000);
    assert.equal(typedData.message.nonce, 0);
    assert.deepEqual(typedData.types.Permit, [
      { name: "owner",    type: "address" },
      { name: "spender",  type: "address" },
      { name: "value",    type: "uint256" },
      { name: "nonce",    type: "uint256" },
      { name: "deadline", type: "uint256" },
    ]);
  });

  it("resolves domain via eip712Domain()", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 } });
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData);
    assert.equal(typedData.domain.name, "USD Coin");
    assert.equal(typedData.domain.version, "2");
    assert.equal(typedData.domain.chainId, 8453);
  });

  it("falls back to name() + override when eip712Domain() reverts", async () => {
    globalThis.fetch = makeMockFetch({ revertDomain: true, name: "USD Coin" });
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData);
    assert.equal(typedData.domain.name, "USD Coin");
    assert.equal(typedData.domain.version, "2");
  });

  it("auto-fetches nonce when not supplied", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 }, nonce: 5n });
    const params = { ...BASE_PARAMS, nonce: undefined };
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, params, mockSignTypedData);
    assert.equal(typedData.message.nonce, 5);
  });

  it("uses supplied nonce without RPC call", async () => {
    let nonceCalled = false;
    globalThis.fetch = async (url, init) => {
      const body = JSON.parse(init.body);
      if (body.method === "eth_call" && body.params[0].data.startsWith("0x7ecebe00")) {
        nonceCalled = true;
      }
      return makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 } })(url, init);
    };
    await signPermit(OWNER, BASE_CHAIN, { ...BASE_PARAMS, nonce: 7 }, mockSignTypedData);
    assert.equal(nonceCalled, false);
  });

  it("omits version field in EIP712Domain when token has no version", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "MyToken", version: "", chainId: 8453 } });
    const params = { ...BASE_PARAMS, token: "0x1234567890123456789012345678901234567890" };
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, params, mockSignTypedData);
    const hasVersion = typedData.types.EIP712Domain.some(f => f.name === "version");
    assert.equal(hasVersion, false);
  });

  it("chainId matches CAIP-2 chain segment", async () => {
    globalThis.fetch = makeMockFetch({ eip712Domain: { name: "USD Coin", version: "2", chainId: 8453 } });
    const { typedData } = await signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData);
    assert.equal(typedData.domain.chainId, 8453);
  });

  it("throws when token name is empty and no override exists", async () => {
    globalThis.fetch = makeMockFetch({ revertDomain: true, name: "" });
    const params = { ...BASE_PARAMS, token: "0x0000000000000000000000000000000000000001" };
    await assert.rejects(
      () => signPermit(OWNER, BASE_CHAIN, params, mockSignTypedData),
      /Could not resolve EIP-712 domain/
    );
  });

  it("throws when RPC is unreachable", async () => {
    globalThis.fetch = async () => { throw new TypeError("fetch failed"); };
    await assert.rejects(() => signPermit(OWNER, BASE_CHAIN, BASE_PARAMS, mockSignTypedData));
  });

  it("DAI fallback domain version is 1", async () => {
    globalThis.fetch = makeMockFetch({ revertDomain: true, name: "Dai Stablecoin" });
    const params = { ...BASE_PARAMS, token: "0x6B175474E89094C44Da98b954EedeAC495271d0F" };
    const { typedData } = await signPermit(OWNER, "eip155:1", params, mockSignTypedData);
    assert.equal(typedData.domain.version, "1");
  });

  it("Ethereum USDC fallback domain version is 2", async () => {
    globalThis.fetch = makeMockFetch({ revertDomain: true, name: "USD Coin" });
    const params = { ...BASE_PARAMS, token: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" };
    const { typedData } = await signPermit(OWNER, "eip155:1", params, mockSignTypedData);
    assert.equal(typedData.domain.version, "2");
  });

});
