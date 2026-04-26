/**
 * x402-pay-request.js
 *
 * Make a paid HTTP request to an x402-enabled API endpoint.
 * OWS handles the 402 -> sign -> retry flow automatically.
 *
 * Usage:
 *   node examples/x402-pay-request.js
 */

import { pay } from "@open-wallet-standard/core";

const WALLET_NAME = "my-wallet";
const API_URL = "https://api.cdp.coinbase.com/platform/v1/price?ids=ethereum";

async function main() {
  console.log("Making x402 payment request...");
  console.log("Wallet :", WALLET_NAME);
  console.log("URL    :", API_URL);
  console.log("-".repeat(50));

  try {
    const result = await pay(WALLET_NAME, API_URL, "GET");

    console.log("Status :", result.status);
    console.log("Protocol:", result.protocol);

    if (result.payment) {
      console.log("Payment :", result.payment.amount, result.payment.token, "on", result.payment.network);
    } else {
      console.log("Payment : none required");
    }

    console.log("Response:", result.body.slice(0, 200));
  } catch (err) {
    console.error("Error:", err.message);
    process.exit(1);
  }
}

main();
