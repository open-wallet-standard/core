# Conformance and Security

> Interoperability requirements, test expectations, and security considerations for OWS implementations.

## Conformance Claims

An implementation claiming OWS conformance MUST declare the profiles it supports.

Minimum claim format:

```text
OWS <supported profiles>
```

Examples:

- `OWS Storage + Signing + Policy + EVM Chain Profile`
- `OWS Storage + Signing + Lifecycle + Solana Chain Profile`

An implementation MUST NOT claim complete OWS conformance if it omits any required behavior from a profile it advertises.

## Required Interoperability Artifacts

Conforming implementations SHOULD ship or consume machine-readable test vectors for:

- wallet file decryption and encryption
- API key file resolution and token verification
- policy rule evaluation
- chain-specific address derivation
- transaction and message signing

When two conforming implementations exchange OWS artifacts, the following behaviors MUST remain interoperable:

- wallet files can be parsed and validated consistently
- API key files can be resolved consistently by token hash
- policy files produce the same allow or deny result for the same `PolicyContext`
- canonical chain and account identifiers are preserved without lossy conversion

## Minimum Test Vector Set

Every implementation SHOULD include at least:

1. One wallet file encrypted with scrypt + AES-256-GCM.
2. One API key file encrypted with HKDF-SHA256 + AES-256-GCM.
3. One declarative policy that allows a supported chain.
4. One declarative policy that denies by expiration.
5. One signing vector per supported chain family.
6. One negative vector for each documented error code.

If an implementation supports executable policies, it SHOULD also include fixtures showing:

- successful executable evaluation
- denial on executable failure
- denial on malformed policy result payloads

## Error Consistency

Implementations MUST preserve the error meanings defined by `02-signing-interface.md`.

They MAY add implementation-specific error metadata, but they MUST NOT:

- turn a policy denial into a generic authentication failure
- collapse unsupported-chain errors into malformed-input errors
- treat expired API keys as missing keys

## Security Requirements

### Secret Material

Implementations MUST:

- decrypt wallet or API-key-backed secret material only for the duration of the operation
- zeroize decrypted mnemonic, private key, derived key, and KDF output buffers after use
- avoid writing decrypted secret material to logs, telemetry, or audit records

Implementations SHOULD use hardened memory and process protections where the host platform allows them.

### Credential Handling

Implementations MUST:

- treat owner credentials and API tokens as secrets
- avoid echoing credentials in logs or human-readable errors
- verify API token scope and policy attachments before any token-backed secret is decrypted

Implementations SHOULD avoid environment variables for long-lived secrets unless the surrounding environment is trusted and documented.

### Policy Enforcement

Implementations MUST:

- evaluate built-in policy rules deterministically
- short-circuit on denial when the policy model requires it
- deny the request if an executable policy exits unsuccessfully or returns malformed output

Implementations MUST NOT provide a fallback path that bypasses token-attached policy evaluation.

### Audit Logging

Audit logs MUST be append-only from the point of view of the OWS implementation.

Every operation that releases a bearer artifact (a signature, a signed transaction, an exported secret) or changes what a credential may do (minting or revoking an API key, registering or deleting a policy) MUST be recorded. Signing MUST be recorded independently of broadcasting: the two are separable, so recording only broadcasts leaves signatures that were handed out and submitted elsewhere untraced.

A policy denial MUST be recorded under the same operation as an allow, so that a refused attempt is a record rather than an absence. Recording only successes hides exactly the activity an audit trail exists to surface — a credential repeatedly attempting what its policy forbids.

Audit records SHOULD include:

- operation type
- wallet identifier, for wallet-scoped operations
- chain identifier
- API key identifier when applicable
- allow or deny outcome
- timestamp

Audit records MUST NOT contain raw passphrases, API tokens, mnemonics, or private keys.

## Reference Guidance

`05-key-isolation.md` provides optional implementation guidance for:

- in-process hardening
- memory locking
- signal-driven cache clearing
- subprocess isolation profiles

Those techniques improve security posture, but interoperability depends on the externally visible behavior defined by the core spec.
