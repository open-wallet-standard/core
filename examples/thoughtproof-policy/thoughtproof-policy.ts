#!/usr/bin/env node
/**
 * ThoughtProof Reasoning Policy for Open Wallet Standard
 *
 * Reads a PolicyContext from stdin, calls the ThoughtProof API to verify
 * the transaction's reasoning, and returns a PolicyResult to stdout.
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
  value?: string; // in smallest unit (wei, etc.)
  raw_hex: string;
  data?: string;
}

interface SpendingContext {
  daily_total: string;
  date: string;
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
const TIMEOUT_MS = 30_000;

function weiToEth(weiStr: string): string {
  try {
    const wei = BigInt(weiStr);
    const whole = wei / WEI_PER_ETH;
    const remainder = wei % WEI_PER_ETH;
    if (remainder === 0n) {
      return whole.toString();
    }
    // Format to 6 decimal places max, trimming trailing zeros
    const decimals = remainder.toString().padStart(18, "0");
    const trimmed = decimals.slice(0, 6).replace(/0+$/, "");
    return trimmed ? `${whole}.${trimmed}` : whole.toString();
  } catch {
    return weiStr;
  }
}

function buildClaim(ctx: PolicyContext): string {
  const value = ctx.transaction.value
    ? `${weiToEth(ctx.transaction.value)} ETH`
    : "unknown amount";
  const to = ctx.transaction.to ?? "unknown recipient";
  return `Transfer ${value} to ${to} on ${ctx.chain_id}`;
}

async function callThoughtProof(
  claim: string
): Promise<ThoughtProofResponse | null> {
  const body: ThoughtProofRequest = {
    claim,
    stakeLevel: "high",
    domain: "financial",
  };

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const paymentWallet = process.env.THOUGHTPROOF_PAYMENT_WALLET;
  if (paymentWallet) {
    headers["X-Payment-Wallet"] = paymentWallet;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

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

function mapToResult(response: ThoughtProofResponse | null): PolicyResult {
  if (response === null) {
    return {
      allow: true,
      reason:
        "ThoughtProof unavailable — proceeding (liveness fallback)",
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
        reason:
          "UNCERTAIN: insufficient evidence — escalate to human review",
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

  let ctx: PolicyContext;
  try {
    ctx = JSON.parse(input) as PolicyContext;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      `[thoughtproof-policy] Failed to parse PolicyContext: ${message}\n`
    );
    // Fail-open on parse error so OWS doesn't get stuck
    const result: PolicyResult = {
      allow: true,
      reason: "ThoughtProof policy: invalid context — proceeding (liveness fallback)",
    };
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exit(0);
  }

  const claim = buildClaim(ctx);
  process.stderr.write(`[thoughtproof-policy] Checking claim: ${claim}\n`);

  const response = await callThoughtProof(claim);
  const result = mapToResult(response);

  process.stderr.write(
    `[thoughtproof-policy] Result: allow=${result.allow}${result.reason ? `, reason="${result.reason}"` : ""}\n`
  );

  process.stdout.write(JSON.stringify(result) + "\n");
}

main().catch((err) => {
  process.stderr.write(`[thoughtproof-policy] Fatal error: ${err}\n`);
  // Fail-open on unexpected errors
  const result: PolicyResult = {
    allow: true,
    reason: "ThoughtProof policy: unexpected error — proceeding (liveness fallback)",
  };
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
});
