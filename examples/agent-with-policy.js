/**
 * agent-with-policy.js
 *
 * Create a policy-gated API key for an agent.
 * The agent can only sign on allowed chains and within expiry.
 *
 * Usage:
 *   node examples/agent-with-policy.js
 */

import { createWallet, signMessage } from "@open-wallet-standard/core";
import { writeFileSync, existsSync } from "fs";
import { execSync } from "child_process";

const WALLET_NAME = "agent-treasury";
const POLICY_ID = "base-agent-limits";
const POLICY_FILE = "/tmp/base-agent-limits.json";

function createPolicyFile() {
  const expiry = new Date();
  expiry.setFullYear(expiry.getFullYear() + 1);

  const policy = {
    id: POLICY_ID,
    name: "Base Agent Safety Limits",
    version: 1,
    created_at: new Date().toISOString(),
    rules: [
      { type: "allowed_chains", chain_ids: ["eip155:8453", "eip155:84532"] },
      { type: "expires_at", timestamp: expiry.toISOString() }
    ],
    action: "deny"
  };

  writeFileSync(POLICY_FILE, JSON.stringify(policy, null, 2));
  console.log("Policy file written to:", POLICY_FILE);
  return POLICY_FILE;
}

async function main() {
  console.log("Setting up policy-gated agent wallet...");
  console.log("-".repeat(50));

  // Step 1: Create wallet
  console.log("Step 1: Creating wallet:", WALLET_NAME);
  const wallet = createWallet(WALLET_NAME);
  console.log("EVM address :", wallet.accounts.find(a => a.chain === "evm")?.address);
  console.log("SOL address :", wallet.accounts.find(a => a.chain === "solana")?.address);

  // Step 2: Create and register policy
  console.log("");
  console.log("Step 2: Registering policy:", POLICY_ID);
  createPolicyFile();
  execSync("ows policy create --file " + POLICY_FILE, { stdio: "inherit" });

  // Step 3: Create API key with policy
  console.log("");
  console.log("Step 3: Creating API key for agent...");
  console.log("Run the following command and store the token securely:");
  console.log("");
  console.log("  ows key create --name claude-agent --wallet " + WALLET_NAME + " --policy " + POLICY_ID);
  console.log("");
  console.log("The agent token (ows_key_...) is shown once.");
  console.log("Pass it to your agent as OWS_API_KEY environment variable.");

  // Step 4: Show what the agent can do
  console.log("");
  console.log("-".repeat(50));
  console.log("Agent policy summary:");
  console.log("  Allowed chains : eip155:8453 (Base), eip155:84532 (Base Sepolia)");
  console.log("  Expiry         : 1 year from now");
  console.log("  Access tier    : agent (policy enforced, no passphrase)");
}

main().catch(err => {
  console.error("Error:", err.message);
  process.exit(1);
});
