/**
 * agent-with-presign-check.js
 *
 * Gate an agent's API key with a custom executable policy that has every
 * request checked by an external pre-sign service before OWS decrypts the key.
 *
 * The executable is a one-line script that forwards the PolicyContext to
 * presign-guard (https://github.com/Fizzl13/presign-guard), which decodes
 * transaction.raw_hex (EVM, Solana, XRPL) or typed_data.raw_json, flags
 * unlimited approvals, permits, EIP-7702 delegations and sanctioned or
 * reported addresses, and answers with a PolicyResult:
 * { "allow": ..., "reason": ... }.
 *
 * The check is paid: put a credit key in ~/.ows/presign-guard.key
 * (GET https://presign-guard.fizzl.eu/v1/credits/100, 100 checks for $0.80).
 * Without one, or when the service is unreachable or slow, the request is
 * denied (fail closed).
 *
 * Usage:
 *   node examples/agent-with-presign-check.js
 */

import { createWallet } from "@open-wallet-standard/core";
import { writeFileSync, mkdirSync, chmodSync } from "fs";
import { execSync } from "child_process";
import { homedir } from "os";
import { join } from "path";

const WALLET_NAME = "agent-treasury";
const POLICY_ID = "presign-check";
const POLICY_DIR = join(homedir(), ".ows", "plugins", "policies");
const EXECUTABLE = join(POLICY_DIR, "presign-guard.sh");
const POLICY_FILE = "/tmp/presign-check.json";

// OWS writes the PolicyContext to stdin and kills the executable after 5 s,
// so curl gives up at 4.8 s; a non-zero exit or a body without "allow" denies.
const SCRIPT = `#!/bin/sh
exec curl -s --max-time 4.8 -X POST https://presign-guard.fizzl.eu/v1/check \\
  -H 'content-type: application/json' \\
  -H "x-credit-key: $(cat "$HOME/.ows/presign-guard.key")" \\
  --data-binary @-
`;

function writeExecutable() {
  mkdirSync(POLICY_DIR, { recursive: true });
  writeFileSync(EXECUTABLE, SCRIPT);
  chmodSync(EXECUTABLE, 0o755);
  console.log("Policy executable written to:", EXECUTABLE);
}

function createPolicyFile() {
  const policy = {
    id: POLICY_ID,
    name: "Pre-sign check of every request",
    version: 1,
    created_at: new Date().toISOString(),
    // Declarative rules run first; the executable only sees what they allow.
    rules: [
      { type: "allowed_chains", chain_ids: ["eip155:8453", "eip155:1"] }
    ],
    executable: EXECUTABLE,
    config: {
      allow_orange: false,    // "a person should look" verdicts are denied too
      allow_unchecked: false  // requests the service can't judge are denied
    },
    action: "deny"
  };

  writeFileSync(POLICY_FILE, JSON.stringify(policy, null, 2));
  console.log("Policy file written to:", POLICY_FILE);
  return POLICY_FILE;
}

async function main() {
  console.log("Setting up an agent wallet with a pre-sign check...");
  console.log("-".repeat(50));

  // Step 1: Create wallet
  console.log("Step 1: Creating wallet:", WALLET_NAME);
  const wallet = createWallet(WALLET_NAME);
  console.log("EVM address :", wallet.accounts.find(a => a.chainId.startsWith("eip155:"))?.address);

  // Step 2: Write the executable and register the policy
  console.log("");
  console.log("Step 2: Registering policy:", POLICY_ID);
  writeExecutable();
  createPolicyFile();
  execSync("ows policy create --file " + POLICY_FILE, { stdio: "inherit" });

  // Step 3: Create API key with policy
  console.log("");
  console.log("Step 3: Creating API key for agent...");
  console.log("Run the following command and store the token securely:");
  console.log("");
  console.log("  ows key create --name checked-agent --wallet " + WALLET_NAME + " --policy " + POLICY_ID);
  console.log("");
  console.log("Pass the token (ows_key_...) to your agent as OWS_PASSPHRASE.");

  // Step 4: What the agent will see
  console.log("");
  console.log("-".repeat(50));
  console.log("Every sign request with that token is now checked first, e.g.:");
  console.log("  USDC transfer to a normal address   -> signed");
  console.log("  unlimited USDC approve to an EOA    -> policy denied: presign-guard red:");
  console.log("                                         UNLIMITED_APPROVAL, UNLIMITED_APPROVAL_TO_EOA");
}

main().catch(err => {
  console.error("Error:", err.message);
  process.exit(1);
});
