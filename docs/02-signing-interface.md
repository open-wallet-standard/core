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

Signs an arbitrary message (for authentication, attestation, or off-chain signatures like EIP-712).

```typescript
interface SignMessageRequest {
  walletId: WalletId;
  chainId: ChainId;
  message: string | Uint8Array;
  encoding?: "utf8" | "hex";
  typedData?: TypedData;               // EIP-712 typed data (EVM only)
}

interface SignMessageResult {
  signature: string;
  recoveryId?: number;                 // for secp256k1 recovery
}
```

Message signing follows chain-specific conventions:
- **EVM**: `personal_sign` (EIP-191) or `eth_signTypedData_v4` (EIP-712)
- **Solana**: Ed25519 signature over the raw message bytes
- **Sui**: Intent-prefixed (scope=3) BLAKE2b-256 digest, Ed25519 signature
- **Cosmos**: ADR-036 off-chain signing
- **Filecoin**: Blake2b-256 hash then secp256k1 signing
- **NEAR**: Ed25519 signature over the raw message bytes (parity with Solana). [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md) messages have their own operation, `signNep413Message` (below). Transaction signing is `Ed25519(SHA-256(borsh(Transaction)))`; `encode_signed_transaction` returns `borsh(Transaction) || 0x00 || sig64` (the canonical `borsh(SignedTransaction)`).

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

### `signHash(request: SignHashRequest): Promise<SignMessageResult>`

Signs a raw 32-byte hash without applying any prefix, domain separator, or other transformation.

```typescript
interface SignHashRequest {
  walletId: WalletId;
  chainId: ChainId;
  hashHex: string;                      // 32-byte hex string
}
```

This operation is only defined for secp256k1-backed chains, and Midnight refuses it: its ledger signatures are made over data the wallet builds itself, so it never signs a caller-supplied digest. For EVM, the returned `recoveryId` is the raw `y_parity` value (`0` or `1`), not the EIP-191 / EIP-712 `27` or `28` form.

### `signAuthorization(request: SignAuthorizationRequest): Promise<SignMessageResult>`

Convenience wrapper for EIP-7702 authorization signing.

```typescript
interface SignAuthorizationRequest {
  walletId: WalletId;
  chainId: ChainId;                     // Must resolve to an EVM chain
  address: string;                      // 20-byte delegate target
  nonce: string;                        // Decimal or 0x-prefixed hex
}
```

This operation signs `keccak256(0x05 || rlp([eip155_chain_id(chainId), address, nonce]))`. The selected EVM `chainId` chooses the wallet account, policy context, and the EIP-155 chain ID encoded into the EIP-7702 tuple itself. If a caller needs a nonstandard tuple, such as wildcard chain ID `0`, it should precompute the digest and call `signHash` directly.

### `signNep413Message(request: SignNep413MessageRequest): Promise<SignMessageResult>`

Signs a NEAR [NEP-413](https://github.com/near/NEPs/blob/master/neps/nep-0413.md) off-chain message, the format NEAR wallets use for authentication.

```typescript
interface SignNep413MessageRequest {
  walletId: WalletId;
  chainId: ChainId;                     // Must resolve to a NEAR chain
  message: string;
  nonce: string;                        // 32 bytes, hex-encoded, chosen by the recipient
  recipient: string;                    // e.g. "alice.near" or "myapp.com"; must not be empty
  callbackUrl?: string;
}
```

This operation signs `sha256(borsh(u32 2147484061) || borsh({ message, nonce, recipient, callbackUrl }))` with Ed25519, the same signature `near-api-js`'s `signNep413Message` and NEP-413 wallets produce. The `2^31 + 413` tag guarantees the signature can never authorize a transaction. `signature` is hex-encoded; NEP-413 verifiers usually expect it base64-encoded alongside the `ed25519:` public key and the account ID. With an API token, policies see a `sign_message` request whose `transaction.raw_hex` is the tagged pre-image (`borsh(tag) || borsh(payload)`), and `transaction.chain_extra` carries the decoded fields (`kind: "nep413_message"`, `message`, `nonce`, `recipient`, `callback_url`). Raw `signMessage` on NEAR is still available to the same token, and a raw signature over the 32-byte SHA-256 of a NEP-413 payload is that payload's signature: a policy that restricts NEP-413 recipients has to deny raw 32-byte NEAR messages as well. For a wallet imported from a raw Ed25519 private key, it also has to deny 32-byte raw payloads on the other chains that sign raw Ed25519 with the same key (Solana, TON).

### `signDelegateAction(request: SignDelegateActionRequest): Promise<SignMessageResult>`

Signs a NEAR [NEP-366](https://github.com/near/NEPs/blob/master/neps/nep-0366.md) delegate action (meta-transaction). A relayer wraps the signed delegate action in its own transaction and pays the gas.

```typescript
interface SignDelegateActionRequest {
  walletId: WalletId;
  chainId: ChainId;                     // Must resolve to a NEAR chain
  delegateActionHex: string;            // borsh(DelegateAction), without the NEP-366 prefix
}
```

This operation signs `sha256(borsh(u32 1073742190) || borsh(DelegateAction))` with Ed25519, the same signature `near-api-js`'s `signDelegateAction` produces. The `2^30 + 366` tag guarantees the signature can never authorize a transaction directly. The bytes MUST decode as a `DelegateAction` with no trailing bytes, MUST NOT contain a nested delegate action, and its `public_key` MUST be the wallet's key, because nearcore verifies the signature against that key. Actions newer than `DeleteAccount` (tag 7) are refused. The `SignedDelegateAction` a relayer submits is `delegateActionHex || 00 || signature`.

With an API token, policies see a `sign_transaction` request whose `transaction.raw_hex` is the tagged pre-image (`borsh(tag) || borsh(DelegateAction)`), and `transaction.chain_extra` carries the decoded fields: `kind: "nep366_delegate_action"`, `sender_id`, `receiver_id`, `actions`, `nonce`, `max_block_height`, `public_key` and `total_deposit` (the sum of the `transfer` and `function_call` deposits, which the relayer prepays). Integers are decimal strings, `args` is base64, keys use NEAR's `ed25519:` base58 form, and contract code appears as `code_hash` (base58 SHA-256) and `code_len`. As with NEP-413, a raw 32-byte `signMessage` on NEAR is the same signature as `signDelegateAction` over a payload with that hash, so a policy that restricts delegate actions has to deny raw 32-byte NEAR messages as well.

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
- [EIP-7702: Set Code for EOAs](https://eips.ethereum.org/EIPS/eip-7702)
