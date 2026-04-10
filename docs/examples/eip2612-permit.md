# EIP-2612 Permit Signing

EIP-2612 `permit()` lets users approve an ERC-20 allowance with an off-chain
signature instead of an on-chain `approve()` transaction. A relayer or protocol
contract submits the permit on the user's behalf — no ETH needed for gas.

OWS provides a `signPermit` helper that handles the boilerplate: nonce
fetching, EIP-712 domain resolution (including per-token version quirks), and
typed data construction.

---

## SDK usage
```js
import { signPermit } from "@open-wallet-standard/core/evm/permit";

// ownerAddress : the wallet's EVM address (from createWallet / getWallet)
// signTypedData: the OWS signTypedData binding for this wallet

const sig = await signPermit(ownerAddress, "eip155:8453", {
  token:    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC on Base
  spender:  "0xYourProtocolAddress",
  value:    "1000000",   // 1 USDC (6 decimals)
  deadline: Math.floor(Date.now() / 1000) + 3_600,       // 1 hour
}, owsSignTypedData);

console.log(sig.v, sig.r, sig.s);
// Use on-chain: token.permit(owner, spender, value, deadline, v, r, s)
```

### PermitParams

| Field      | Type     | Required | Description                                      |
|------------|----------|----------|--------------------------------------------------|
| `token`    | string   | yes      | ERC-20 contract address                          |
| `spender`  | string   | yes      | Address to approve                               |
| `value`    | string   | yes      | Amount in base units (e.g. `"1000000"` = 1 USDC) |
| `deadline` | number   | yes      | Unix timestamp — permit invalid after this       |
| `nonce`    | number   | no       | Auto-fetched from chain if omitted               |
| `rpcUrl`   | string   | no       | JSON-RPC endpoint (chain default used if omitted) |

### Return value
```js
{
  signature: "0x...",  // full 65-byte hex (r + s + v)
  v: 27,               // recovery id
  r: "0x...",          // 32-byte hex
  s: "0x...",          // 32-byte hex
  typedData: { ... },  // the signed EIP-712 object (useful for debugging)
}
```

---

## How domain resolution works

Getting the EIP-712 domain separator right is the error-prone part — tokens
differ in which fields they include and what version string they use.
`signPermit` resolves the domain in three stages:

1. **`eip712Domain()`** (EIP-5267) — self-describing; used by USDC v2.2+,
   OpenZeppelin ERC20Permit 5.x, and any future-compliant token.
2. **Well-known override table** — covers USDC (`"2"`), DAI (`"1"`), and
   others whose domain is fixed and well-established.
3. **`name()` + default version `"1"`** — generic fallback for any other
   EIP-2612-compliant token.

Tokens that omit `version` from their domain are handled correctly — the
`EIP712Domain` type array is built dynamically to match exactly what the
token expects.

### Supported tokens (override table)

| Token | Chains | Version |
|-------|--------|---------|
| USDC  | Base, Ethereum, Polygon, Arbitrum, Optimism | `"2"` |
| DAI   | Ethereum | `"1"` |
| USDT  | Base | `"1"` |

---

## Supported chains (default RPC)

| CAIP-2        | Chain          |
|---------------|----------------|
| `eip155:1`    | Ethereum       |
| `eip155:8453` | Base           |
| `eip155:137`  | Polygon        |
| `eip155:42161`| Arbitrum One   |
| `eip155:10`   | Optimism       |

Pass `rpcUrl` for any other chain.

---

## Security notes

- Set a tight `deadline` (30–60 minutes for interactive flows).
- Nonces are single-use — the on-chain `permit()` call increments the nonce,
  invalidating any other signatures with the same nonce.
- OWS never exposes the private key; signing happens inside the OWS core.
