/**
 * x402-discover-services.js
 *
 * Discover x402-enabled services from the Bazaar directory.
 * Discovery lives in the `ows` CLI, not the Node SDK, so this example drives
 * the CLI through child_process.
 *
 * Prereqs:
 *   npm install -g @open-wallet-standard/core
 *
 * Usage:
 *   node examples/x402-discover-services.js
 *   node examples/x402-discover-services.js ai
 */

import { execFileSync } from "child_process";

const query = process.argv[2];

function main() {
  console.log("Discovering x402 services" + (query ? " matching: " + query : "") + "...");
  console.log("-".repeat(50));

  try {
    // ows pay discover [--query <q>] [--limit N] [--offset N]
    const args = ["pay", "discover", "--limit", "10"];
    if (query) args.push("--query", query);
    execFileSync("ows", args, { stdio: "inherit" });
  } catch (err) {
    console.error("Discovery failed:", err.message);
    process.exit(1);
  }
}

main();
