/**
 * Offline tests for pulse-policy.mjs: runs the executable exactly as OWS does (PolicyContext on stdin, PolicyResult
 * on stdout) against a local stand-in for check_tx, so no network is needed and the results never change.
 *
 * Usage: node --test examples/solana-pulse-policy/test.mjs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const POLICY = fileURLToPath(new URL("./pulse-policy.mjs", import.meta.url));
const SOLANA = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const TX_HEX = "01" + "00".repeat(64) + "8001000102"; // any bytes will do: the stand-in decides the verdict

// The stand-in returns whatever the current test sets in `reply`, and records what it was sent in `seen`.
let reply = { status: 200, body: { verdict: "OK", summary: "OK: nothing risky found." } };
let seen = null;
const server = createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    seen = { body: JSON.parse(raw || "{}"), apiKey: req.headers["x-api-key"] };
    if (reply.hang) return;
    res.writeHead(reply.status, { "content-type": "application/json" });
    res.end(JSON.stringify(reply.body));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const endpoint = `http://127.0.0.1:${server.address().port}/api/tools/check_tx`;
test.after(() => server.close());

function run(ctx, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [POLICY], { env: { ...process.env, PULSE_API_KEY: "", ...env } });
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.on("close", (code) => resolve({ code, result: JSON.parse(out) }));
    child.stdin.end(typeof ctx === "string" ? ctx : JSON.stringify(ctx));
  });
}
const ctx = (over = {}, config = {}) => ({
  chain_id: SOLANA, wallet_id: "w", api_key_id: "k", request_type: "sign_transaction",
  transaction: { effects: [], raw_hex: TX_HEX }, spending: { daily_total: "0", date: "2026-10-27" },
  timestamp: "2026-10-27T00:00:00Z", policy_config: { endpoint, timeout_ms: 1500, ...config }, ...over,
});

test("OK is allowed, and the transaction is sent to check_tx as base64", async () => {
  reply = { status: 200, body: { verdict: "OK", summary: "OK" } };
  const { code, result } = await run(ctx());
  assert.equal(code, 0);
  assert.deepEqual(result, { allow: true });
  assert.equal(seen.body.tx, Buffer.from(TX_HEX, "hex").toString("base64"));
});

test("BLOCK is denied with Pulse's summary as the reason", async () => {
  reply = { status: 200, body: { verdict: "BLOCK", summary: "BLOCK: Instruction 2 lets X move up to 1000000000000 base units." } };
  const { result } = await run(ctx());
  assert.equal(result.allow, false);
  assert.match(result.reason, /Instruction 2 lets X move/);
});

test("REVIEW is denied by default, allowed only when config.allow lists it", async () => {
  reply = { status: 200, body: { verdict: "REVIEW", summary: "REVIEW: The blockhash has expired." } };
  assert.equal((await run(ctx())).result.allow, false);
  assert.equal((await run(ctx({}, { allow: ["OK", "REVIEW"] }))).result.allow, true);
});

test("fails closed: unreachable, timed out, HTTP errors and 402 are all denials", async () => {
  assert.match((await run(ctx({}, { endpoint: "http://127.0.0.1:9/x" }))).result.reason, /unreachable/);
  reply = { hang: true };
  assert.match((await run(ctx())).result.reason, /timed out/);
  reply = { status: 400, body: { error: "Invalid input." } };
  assert.match((await run(ctx())).result.reason, /HTTP 400: Invalid input,/);
  reply = { status: 402, body: {} };
  assert.match((await run(ctx())).result.reason, /free checks used up/);
  reply = { status: 200, body: { unexpected: true } };
  assert.equal((await run(ctx())).result.allow, false);
});

test("PULSE_API_KEY is sent as x-api-key", async () => {
  reply = { status: 200, body: { verdict: "OK" } };
  await run(ctx(), { PULSE_API_KEY: "pulse_trial_example" });
  assert.equal(seen.apiKey, "pulse_trial_example");
});

test("sign_message and sign_hash on Solana are denied unless config.allow_messages", async () => {
  for (const request_type of ["sign_message", "sign_hash"]) {
    const { result } = await run(ctx({ request_type }));
    assert.equal(result.allow, false);
    assert.match(result.reason, /can authorize a transaction without a check/);
    assert.equal((await run(ctx({ request_type }, { allow_messages: true }))).result.allow, true);
  }
});

test("other chains and read_balance pass through; missing bytes and bad input are denied", async () => {
  assert.equal((await run(ctx({ chain_id: "eip155:8453" }))).result.allow, true);
  assert.equal((await run(ctx({ request_type: "read_balance", transaction: undefined }))).result.allow, true);
  assert.match((await run(ctx({ transaction: { effects: [], raw_hex: "" } }))).result.reason, /no transaction bytes/);
  assert.match((await run(ctx({ transaction: { effects: [], raw_hex: "abc" } }))).result.reason, /no transaction bytes/);
  assert.match((await run("not json")).result.reason, /could not read the PolicyContext/);
});
