# Signing Interface

> The core operations exposed by an OWS implementation: signing, sending, and message signing.

## Interface Definition

### `sign(request: SignRequest): Promise<SignResult>`

Signs a transaction without broadcasting it. Returns the signed transaction bytes.
```typescript
interface SignRequest {
  walletId: WalletId;
  chainId: ChainId;       // CAIP-2 or supported shorthand alias
  transactionHex: string; // hex-encoded serialized transaction bytes
}

interface SignResult {
  signature: string;
  recoveryId?: number;
}
```

**Flow:**
1. Resolve `walletId` → wallet file
2. Resolve `chainId` → chain plugin
3. Authenticate caller: owner (passphrase/passkey) or agent (API key)
4. If agent: verify wallet is in API key's `walletIds` scope; evaluate API key's policies against the transaction
5. If owner: skip policy evaluation (sudo access)
6. If policies pass (or owner), decrypt key material
7. Sign via chain plugin's signer
8. Wipe key material
9. Return the signature (and recovery ID when applicable)

### `signAndSend(request: SignAndSendRequest): Promise<SignAndSendResult>`

Signs, encodes, and broadcasts a transaction.
```typescript
interface SignAndSendRequest extends SignRequest {
  rpcUrl?: string;
}

interface SignAndSendResult {
  transactionHash: string;
}
```

The signer implementation handles transaction encoding and submission through an implementation-defined transport. `rpcUrl` is an optional endpoint override for surfaces that support direct endpoint selection.

An implementation that exposes `signAndSend`:

- MUST perform the same authentication and policy checks as `sign`
- MUST return a stable transaction identifier when the broadcast succeeds
- MUST fail clearly if the target transport is unavailable or unsupported
- MAY expose richer transport metadata in implementation-specific fields

### `signMessage(request: SignMessageRequest): Promise<SignMessageResult>`

Signs a message using the chain's recognized off-chain message-signing convention, where one exists.
```typescript
interface SignMessageRequest {
  walletId: WalletId;
  chainId: ChainId;
  message: string | Uint8Array;
  encoding?: "utf8" | "hex";
}

interface SignMessageResult {
  signature: string;
  recoveryId?: number;                 // for secp256k1 chains (EVM, Bitcoin, Tron)
}
```

#### Design intent

`signMessage` is a **user-facing, cross-chain off-chain signing primitive**. It is not a raw-byte signing escape hatch — use `sign` for that.

The interface is intentionally restricted to chains that have a recognized, ecosystem-wide off-chain message signing convention. This means:

- Signatures produced by `signMessage` on one chain are **not interoperable** with other chains, even if both use the same underlying curve. The chain-specific envelope (prefix, intent hash, domain tag, etc.) is what makes a signature meaningful and verifiable on that chain.
- Adding `signMessage` support for a new chain requires a **clearly defined, widely-adopted convention** for that chain — not just the ability to sign bytes.
- Chains without a recognized convention SHOULD return `CHAIN_NOT_SUPPORTED` rather than silently signing raw bytes, which would imply interoperability that does not exist.

#### Behavior by chain

| Chain | Convention | Bytes signed |
|-------|-----------|--------------|
| EVM | EIP-191 `personal_sign` | `\x19Ethereum Signed Message:\n` + length + message |
| Bitcoin | Bitcoin Signed Message | `\x18Bitcoin Signed Message:\n` + varint(len) + message |
| Tron | TRON personal-message prefix | `\x19TRON Signed Message:\n` + length + message |
| Sui | Personal message intent | Intent prefix (scope=3) + BCS-encoded message, BLAKE2b-256 hashed |
| Cosmos | ADR-036 | Amino-encoded `MsgSignData` with `chain_id: ""` |
| Filecoin | — | Blake2b-256 hash of message bytes, secp256k1 signed |
| Solana | — | Raw message bytes, Ed25519 signed |
| TON | — | Raw message bytes, Ed25519 signed |
| XRPL | unsupported | No recognized canonical convention yet |

> **Note on Filecoin, Solana, and TON:** These chains currently sign raw or hashed bytes without a recognized off-chain message envelope. This behavior is preserved for compatibility but callers should be aware that the resulting signatures are not verifiable through any standard wallet verification flow on those chains. Future versions may introduce chain-specific conventions as they emerge.

#### Adding support for new chains

When adding `signMessage` for a new chain (e.g. Nano, Stellar, Aptos):

1. Identify the chain's **canonical off-chain message signing specification** — a finalized EIP, BIP, or equivalent standards document.
2. If no specification exists, return `CHAIN_NOT_SUPPORTED` and document why in the chain plugin.
3. Do not sign raw bytes under `signMessage` — use `sign` for arbitrary byte signing.
4. Document the exact bytes signed in the chain plugin and in the table above.

#### EIP-712 typed data

For EIP-712 structured data on EVM chains, use `signTypedData` instead. The `signMessage` interface does not accept typed data — this separation keeps the API surface clean and avoids overloading a single method with two distinct signing semantics.

### `signTypedData(request: SignTypedDataRequest): Promise<SignMessageResult>`

Signs EIP-712 typed structured data. This is a dedicated operation separate from `signMessage` to provide a clean SDK interface for typed data signing without overloading the message signing API.
```typescript
interface SignTypedDataRequest {
  walletId: WalletId;
  chainId: ChainId;                    // Must be an EVM chain
  typedDataJson: string;               // JSON string of EIP-712 typed data
}
```

The `typedDataJson` field must be a JSON string containing the standard EIP-712 fields: `types`, `primaryType`, `domain`, and `message`.
```json
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "chainId", "type": "uint256"}
    ],
    "Transfer": [
      {"name": "to", "type": "address"},
      {"name": "amount", "type": "uint256"}
    ]
  },
  "primaryType": "Transfer",
  "domain": {"name": "MyDApp", "chainId": "1"},
  "message": {"to": "0xabc...", "amount": "1000"}
}
```

Returns a `SignMessageResult` with the signature and recovery ID. Only supported for EVM chains.

## Serialized Transaction Format

Current OWS implementations accept **already-serialized transaction bytes encoded as hex**. OWS signs those bytes, and `signAndSend` implementations submit the signed payload using the transport required by the target chain.

## Error Handling

| Code | Meaning |
|---|---|
| `WALLET_NOT_FOUND` | No wallet with the given ID exists |
| `CHAIN_NOT_SUPPORTED` | No signer is available for the given chain |
| `INVALID_PASSPHRASE` | Vault passphrase was incorrect |
| `INVALID_INPUT` | Request payload or arguments were malformed |
| `CAIP_PARSE_ERROR` | The chain identifier could not be parsed |
| `POLICY_DENIED` | Request was rejected by the policy engine |
| `API_KEY_NOT_FOUND` | The provided API token did not resolve to a key |
| `API_KEY_EXPIRED` | The API key has expired |

## Concurrency

Current implementations do not provide a per-wallet nonce manager or explicit same-wallet request serialization. Callers that need strict nonce coordination must currently handle it at a higher level.

## References

- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)
- [EIP-712: Typed Structured Data](https://eips.ethereum.org/EIPS/eip-712)
- [ADR-036: Arbitrary Message Signing](https://docs.cosmos.network/main/build/architecture/adr-036-arbitrary-signature)
- [Bitcoin Signed Message](https://en.bitcoin.it/wiki/Message_signing)
