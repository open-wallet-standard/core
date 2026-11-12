#!/usr/bin/env node
/**
 * pulse-policy.mjs
 *
 * An OWS custom executable policy for Solana: before an agent's API key signs a Solana transaction, ask
 * Solana Pulse's check_tx (https://github.com/Timothymycompc/solana-pulse-ai-agent-gateway) whether it is safe
 * to sign. Pulse simulates the transaction on mainnet and returns OK, REVIEW or BLOCK with its reasons (drainer
 * patterns, token approvals, authority changes, unknown programs, expired blockhash, already landed, ...).
 *
 * Protocol (docs/03-policy-engine.md): reads the PolicyContext JSON on stdin, writes one PolicyResult to stdout.
 * Only OK is allowed. Fails closed: if Pulse can't be reached or can't judge the transaction, signing is denied.
 *
 * Optional PolicyContext.policy_config (the policy file's "config"):
 *   { "endpoint": "https://.../api/tools/check_tx", "allow": ["OK"], "timeout_ms": 20000, "allow_messages": false }
 * Optional environment: PULSE_API_KEY (sent as x-api-key; lifts the 25 free calls a day per caller).
 */

const DEFAULT_ENDPOINT = "https://solana-pulse-gateway-1021990235790.us-central1.run.app/api/tools/check_tx";

const result = (allow, reason) => {
  process.stdout.write(JSON.stringify(reason ? { allow, reason } : { allow }) + "\n");
  process.exit(0);
};

let input = "";
for await (const chunk of process.stdin) input += chunk;

let ctx;
try {
  ctx = JSON.parse(input);
} catch {
  result(false, "Solana Pulse policy: could not read the PolicyContext JSON");
}

const config = ctx.policy_config ?? {};
const allowed = config.allow ?? ["OK"];

// Only Solana transactions are checked. Pair this policy with an allowed_chains rule so the key can't sign
// elsewhere without a check.
if (!String(ctx.chain_id ?? "").startsWith("solana:")) result(true);
// Reading a balance produces no signature.
if (ctx.request_type === "read_balance") result(true);
// Solana signs messages with no prefix, so a sign_message (or sign_hash) over a transaction's message bytes is a
// valid signature for that transaction, and would skip the check. Denied unless the policy opts in.
if (ctx.request_type !== "sign_transaction") {
  if (config.allow_messages === true) result(true);
  result(false, `Solana Pulse policy: ${ctx.request_type} on Solana can authorize a transaction without a check; set config.allow_messages to permit it`);
}

const hex = String(ctx.transaction?.raw_hex ?? "").replace(/^0x/, "");
if (!hex || hex.length % 2) result(false, "Solana Pulse policy: no transaction bytes to check");
const tx = Buffer.from(hex, "hex").toString("base64");

let res, body;
try {
  res = await fetch(config.endpoint ?? DEFAULT_ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(process.env.PULSE_API_KEY ? { "x-api-key": process.env.PULSE_API_KEY } : {}),
    },
    body: JSON.stringify({ tx }),
    signal: AbortSignal.timeout(config.timeout_ms ?? 20000),
  });
  body = await res.json().catch(() => ({}));
} catch (err) {
  result(false, `Solana Pulse policy: check_tx unreachable (${err.name === "TimeoutError" ? "timed out" : err.message}), so not signing`);
}

if (res.status === 402) result(false, "Solana Pulse policy: free checks used up for today; set PULSE_API_KEY or pay per call, so not signing");
if (!res.ok || typeof body.verdict !== "string") {
  result(false, `Solana Pulse policy: check_tx answered HTTP ${res.status}${body.error ? `: ${String(body.error).replace(/\.$/, "")}` : ""}, so not signing`);
}

if (allowed.includes(body.verdict)) result(true);
result(false, `Solana Pulse check_tx: ${body.summary ?? body.verdict}`);
