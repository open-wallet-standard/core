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

## Prerequisites

    npm install -g @open-wallet-standard/core
    ows wallet create --name agent-treasury

Get test USDC on Base Sepolia: https://faucet.circle.com

## Making a upto Payment

x402 payments run through the CLI via :

    # Make a paid request to an x402-enabled endpoint
    ows pay request https://api.example.com/summarize
      --wallet agent-treasury
      --method POST
      --body '{"text": "Long document..."}'

The CLI handles the full 402 -> sign -> retry flow automatically.
Output includes the settled amount and transaction details.

## Discover Available Services

    # List all x402-enabled services
    ows pay discover

    # Filter by keyword
    ows pay discover ai
    ows pay discover summarize

## Post-Settlement Accounting Script

After each payment, track authorized / settled / released amounts.
This belongs in your app layer, not in OWS itself.

See  for a runnable Node.js script
that shells out to  and tracks per-session accounting.

## OWS vs App Layer Boundary

| Responsibility | OWS | Your App |
|---|---|---|
| Sign the payment authorization | yes | no |
| Handle 402 -> retry flow | yes | no |
| Track authorized vs settled amounts | no | yes |
| Enforce per-session spending caps | no | yes |
| Reconcile with external ledger | no | yes |

OWS provides the settled amount in the CLI output.
Everything above that is application-layer accounting.
