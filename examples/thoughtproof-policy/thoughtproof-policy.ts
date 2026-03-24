#!/usr/bin/env node
/**
 * ThoughtProof Reasoning Policy for Open Wallet Standard
 *
 * Reads a PolicyContext from stdin, calls the ThoughtProof API to verify
 * the transaction's reasoning, and returns a PolicyResult to stdout.
 *
 * Verdict mapping:
 *   ALLOW     → allow: true
 *   BLOCK     → allow: false (fail-closed)
 *   UNCERTAIN → allow: false (fail-closed, escalate to human)
 *   API error → allow: true  (fail-open, liveness fallback — logged to stderr)
 *   Parse err → allow: false (fail-closed — invalid context is never safe)
 */

interface PolicyContext {
  chain_id: string;
  wallet_id: string;
  api_key_id: string;
  transaction: TransactionContext;
  spending: SpendingContext;
  timestamp: string;
}

interface TransactionContext {
  to?: string;
  value?: string; // in smallest unit (wei, lamports, etc.)
  raw_hex: string;
  data?: string;
}

interface SpendingContext {
  daily_total: string;
  date: string;
}

// Optional config from the OWS policy.json "config" field
interface PolicyConfig {
  stake_level?: "low" | "medium" | "high" | "critical";
  domain?: string;
  context?: string; // Human-readable intent context passed to ThoughtProof
  timeout_ms?: number;
  fail_open?: boolean; // Override liveness behaviour (default: true)
}

interface PolicyResult {
  allow: boolean;
  reason?: string;
  policy_id?: string;
}

interface ThoughtProofRequest {
  claim: string;
  stakeLevel: string;
  domain: string;
}

interface ThoughtProofResponse {
  verdict: "ALLOW" | "BLOCK" | "UNCERTAIN";
  objections?: string[];
  confidence?: number;
}

const WEI_PER_ETH = 1_000_000_000_000_000_000n;
const THOUGHTPROOF_API_URL = "https://api.thoughtproof.ai/v1/check";
const DEFAULT_TIMEOUT_MS = 30_000;

function weiToEth(weiStr: string): string {
  try {
    const wei = BigInt(weiStr);
    const whole = wei / WEI_PER_ETH;
    const remainder = wei % WEI_PER_ETH;
    if (remainder === 0n) return whole.toString();
    const decimals = remainder.toString().padStart(18, "0");
    const trimmed = decimals.slice(0, 6).replace(/0+$/, "");
    return trimmed ? `${whole}.${trimmed}` : whole.toString();
  } catch {
    return weiStr;
  }
}

function buildClaim(ctx: PolicyContext, config: PolicyConfig): string {
  const value = ctx.transaction.value
    ? `${weiToEth(ctx.transaction.value)} ETH`
    : "unknown amount";
  const to = ctx.transaction.to ?? "unknown recipient";

  // Base claim: what is happening
  let claim = `Transfer ${value} to ${to} on ${ctx.chain_id}`;

  // Append agent-provided intent context if configured
  if (config.context) {
    claim += `. Context: ${config.context}`;
  }

  // Append daily spending context for proportionality check
  if (ctx.spending.daily_total && ctx.spending.daily_total !== "0") {
    const dailyEth = weiToEth(ctx.spending.daily_total);
    claim += `. Daily total so far: ${dailyEth} ETH`;
  }

  return claim;
}

async function callThoughtProof(
  claim: string,
  config: PolicyConfig
): Promise<ThoughtProofResponse | null> {
  const stakeLevel = config.stake_level ?? "high";
  const domain = config.domain ?? "financial";
  const timeoutMs = config.timeout_ms ?? DEFAULT_TIMEOUT_MS;

  const body: ThoughtProofRequest = { claim, stakeLevel, domain };

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const paymentWallet = process.env.THOUGHTPROOF_PAYMENT_WALLET;
  if (paymentWallet) {
    headers["X-Payment-Wallet"] = paymentWallet;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(THOUGHTPROOF_API_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      process.stderr.write(
        `[thoughtproof-policy] API error: HTTP ${response.status}\n`
      );
      return null;
    }

    return (await response.json()) as ThoughtProofResponse;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `[thoughtproof-policy] API call failed: ${message}\n`
    );
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function mapToResult(
  response: ThoughtProofResponse | null,
  config: PolicyConfig
): PolicyResult {
  // API unavailable — liveness fallback (configurable, default: fail-open)
  if (response === null) {
    const failOpen = config.fail_open !== false;
    return failOpen
      ? {
          allow: true,
          reason: "ThoughtProof unavailable — proceeding (liveness fallback)",
        }
      : {
          allow: false,
          reason: "ThoughtProof unavailable — blocking (fail-closed mode)",
          policy_id: "thoughtproof-reasoning",
        };
  }

  switch (response.verdict) {
    case "ALLOW":
      return { allow: true };

    case "BLOCK": {
      const firstObjection =
        response.objections?.[0] ?? "Transaction blocked by reasoning policy";
      return {
        allow: false,
        reason: firstObjection,
        policy_id: "thoughtproof-reasoning",
      };
    }

    case "UNCERTAIN":
      return {
        allow: false,
        reason: "UNCERTAIN: insufficient evidence — escalate to human review",
        policy_id: "thoughtproof-reasoning",
      };

    default:
      return {
        allow: false,
        reason: `Unexpected verdict: ${(response as ThoughtProofResponse).verdict}`,
        policy_id: "thoughtproof-reasoning",
      };
  }
}

async function main(): Promise<void> {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  // Parse PolicyContext — fail-closed on invalid input (never safe to proceed)
  let ctx: PolicyContext;
  try {
    ctx = JSON.parse(input) as PolicyContext;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `[thoughtproof-policy] Failed to parse PolicyContext: ${message}\n`
    );
    const result: PolicyResult = {
      allow: false,
      reason: "ThoughtProof policy: invalid context — blocking (fail-closed)",
      policy_id: "thoughtproof-reasoning",
    };
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exit(0);
  }

  // Read config from environment (set by OWS from policy.json config field)
  let config: PolicyConfig = {};
  const configEnv = process.env.OWS_POLICY_CONFIG;
  if (configEnv) {
    try {
      config = JSON.parse(configEnv) as PolicyConfig;
    } catch {
      process.stderr.write(
        `[thoughtproof-policy] Warning: could not parse OWS_POLICY_CONFIG, using defaults\n`
      );
    }
  }

  const claim = buildClaim(ctx, config);
  process.stderr.write(`[thoughtproof-policy] Checking claim: ${claim}\n`);

  const response = await callThoughtProof(claim, config);
  const result = mapToResult(response, config);

  process.stderr.write(
    `[thoughtproof-policy] Result: allow=${result.allow}${result.reason ? `, reason="${result.reason}"` : ""}\n`
  );

  process.stdout.write(JSON.stringify(result) + "\n");
}

main().catch((err) => {
  process.stderr.write(`[thoughtproof-policy] Fatal error: ${err}\n`);
  // Fatal errors → fail-closed (unknown state is never safe)
  const result: PolicyResult = {
    allow: false,
    reason: "ThoughtProof policy: fatal error — blocking (fail-closed)",
    policy_id: "thoughtproof-reasoning",
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
});
