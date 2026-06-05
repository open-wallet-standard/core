/**
 * x402-pay-request.js
 *
 * Make a paid request to an x402-enabled API endpoint.
 * x402 lives in the `ows` CLI, not the Node SDK, so this example drives the
 * CLI through child_process. The CLI handles the 402 -> sign -> retry flow.
 *
 * Prereqs:
 *   npm install -g @open-wallet-standard/core
 *   ows wallet create --name my-wallet
 *
 * Usage:
 *   node examples/x402-pay-request.js
 */

import { execFileSync } from "child_process";

const WALLET_NAME = "my-wallet";
const API_URL = "https://api.cdp.coinbase.com/platform/v1/price?ids=ethereum";

function main() {
  console.log("Making an x402 payment request through the ows CLI...");
  console.log("Wallet :", WALLET_NAME);
  console.log("URL    :", API_URL);
  console.log("-".repeat(50));

  try {
    // ows pay request <url> --wallet <name> [--method GET] [--body '{...}']
    // Add "--no-passphrase" for a wallet created without a passphrase.
    execFileSync(
      "ows",
      ["pay", "request", API_URL, "--wallet", WALLET_NAME, "--method", "GET"],
      { stdio: "inherit" }
    );
  } catch (err) {
    console.error("Payment request failed:", err.message);
    process.exit(1);
  }
}

main();
