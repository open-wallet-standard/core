# x402 Usage-Based Settlement

This example shows the **upto** (usage-based) settlement pattern
for agent payments where the final amount is not known until the task completes.

## How upto Settlement Works

    1. Agent authorizes max amount  ->  service begins work
    2. Service completes task        ->  settles actual amount
    3. Remaining headroom released   ->  wallet balance updated

| Pattern | Amount at auth | Amount settled |
|---|---|---|
| exact | Known upfront | Same as authorized |
| upto  | Max cap authorized | Actual cost (<=max) |

## Minimal Example

    import { pay } from "@open-wallet-standard/core";

    const result = await pay(
      "agent-treasury",
      "https://api.example.com/summarize",
      "POST",
      JSON.stringify({ text: "Long document..." })
    );

    if (result.payment) {
      console.log("Settled :", result.payment.amount, result.payment.token);
    }

## Post-Settlement Accounting

After a upto settlement, track three values:

| Value | Description |
|---|---|
| Authorized | Max amount locked at request time |
| Settled | Actual amount charged by service |
| Released | Authorized minus settled (returned to balance) |

    class UptoBillingTracker {
      constructor() { this.entries = []; }

      record(requestId, authorizedAmount, result) {
        const settled = result.payment ? parseFloat(result.payment.amount) : 0;
        const authorized = parseFloat(authorizedAmount);
        const released = authorized - settled;
        this.entries.push({ requestId, authorized, settled, released });
        return { authorized, settled, released };
      }

      summary() {
        return {
          totalAuthorized : this.entries.reduce((s, e) => s + e.authorized, 0),
          totalSettled    : this.entries.reduce((s, e) => s + e.settled, 0),
          totalReleased   : this.entries.reduce((s, e) => s + e.released, 0),
        };
      }
    }

## OWS vs App Layer Boundary

| Responsibility | OWS | Your App |
|---|---|---|
| Sign the payment authorization | yes | no |
| Handle 402 -> retry flow | yes | no |
| Track authorized vs settled amounts | no | yes |
| Enforce per-session spending caps | no | yes |
| Reconcile with external ledger | no | yes |

OWS provides result.payment.amount (the settled amount).
Everything above that is application-layer accounting.

## Running This Example

    npm install -g @open-wallet-standard/core
    ows wallet create --name agent-treasury
    node examples/x402-upto-settlement.js

Get test USDC on Base Sepolia: https://faucet.circle.com
