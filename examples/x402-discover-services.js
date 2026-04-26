/**
 * x402-discover-services.js
 *
 * Discover x402-enabled payable services in the OWS marketplace.
 *
 * Usage:
 *   node examples/x402-discover-services.js
 *   node examples/x402-discover-services.js ai
 */

import { discover } from "@open-wallet-standard/core";

const query = process.argv[2] || null;

async function main() {
  console.log("Discovering x402 services" + (query ? " matching: " + query : "") + "...");
  console.log("-".repeat(50));

  try {
    const result = await discover(query, 10, 0);

    console.log("Total services found:", result.total);
    console.log("Showing:", result.services.length);
    console.log("");

    for (const svc of result.services) {
      console.log("Name    :", svc.name);
      console.log("URL     :", svc.url);
      console.log("Price   :", svc.price);
      console.log("Network :", svc.network);
      console.log("Tags    :", svc.tags.join(", ") || "none");
      console.log("Desc    :", svc.description);
      console.log("-".repeat(50));
    }

    if (result.total > result.services.length) {
      console.log("More services available — use offset to page through results.");
    }
  } catch (err) {
    console.error("Error:", err.message);
    process.exit(1);
  }
}

main();
