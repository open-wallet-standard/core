# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Validate Cardano submission responses against the locally computed transaction
  ID instead of accepting any 64-character response. Reject malformed or mismatched
  hashes, and accept matching JSON/bare hashes with surrounding whitespace or uppercase hex.

### Added
- Cardano support across mainnet, preprod and preview (`cip34:` CAIP-2 namespace):
  Ed25519-BIP32 curve with CIP-3 Icarus master-key derivation, CIP-1852 payment and
  stake paths, Shelley base/enterprise/reward addresses, CIP-8 COSE message signing,
  CBOR transaction signing and submission, and ADA/native-asset balance queries via
  Koios
- `PolicyContext.request_type` names the operation being authorized
  (`sign_transaction`, `sign_message`, `sign_hash`, `sign_typed_data`)
- `TransactionContext.effects`: per-address, per-asset movement a transaction causes,
  populated by chains whose signer implements flow analysis (Cardano today)
- `TransactionContext.chain_extra`: opaque per-chain JSON for detail `effects` cannot
  carry. Cardano reports contingent collateral loss in `chain_extra.collateral_effects`
- `ChainSigner`: `make_transaction_context`, `default_derivation_paths`, `encode_keys`,
  `verify_sign_message_address` and `transaction_context_needs_rpc`, all defaulted
- Optional `address` argument on `sign_message` / `sign_typed_data`, which refuses to
  sign for an address the key does not derive (`AddressMismatch`)

### Breaking

These are contract changes and warrant a major version; the number itself is set by
the release tag (`.github/workflows/version-bump.yml`).

Policy contract, as executable policies see it on stdin:

- `PolicyContext.transaction` is now **optional** and is omitted for `sign_typed_data`,
  which previously carried a `TransactionContext` with `raw_hex: ""`. **A policy that
  detected typed data by that empty string can fail open**: written as
  `tx = payload.get("transaction") or {}`, the `raw_hex == ""` test becomes false, so a
  policy that denied typed data signing now allows it, with no error and no log entry.
  Branch on `request_type == "sign_typed_data"` instead. See `docs/03-policy-engine.md`
  for the failure direction of each policy style. Rust consumers break at compile time.
- `TransactionContext.to` and `.value` are removed in favour of `effects`. Neither was
  ever populated by any chain, so a policy reading them always saw `null`.
- `TransactionEffect.diff` amounts are signed decimal **strings**, not integers: wei
  overflows an `i64` above ~9.22 ETH, and a JSON integer above 2^53 does not survive
  `JSON.parse`. Parse with `int()` / `BigInt()`.

Rust API:

- `ChainSigner::sign_message` gains an `address: Option<&str>` parameter
- `ows_pay::fund::get_balances` gains an `rpc_url` parameter (required for Cardano)
- `BalanceInfo.value` and `.price` are `Option<f64>`, absent on chains without pricing
- `enforce_policy_and_decrypt_key` is split into `load_authorized_wallet` and
  `enforce_policies_and_decrypt_key`
- `signer_for_chain` now takes `&Chain` instead of `ChainType` (so Cardano can see the
  network reference), and both it and `signer_for_chain_type` return
  `Result<Box<dyn ChainSigner>, SignerError>`: Cardano rejects a `cip34:` reference it
  does not know (`SignerError::UnsupportedChain`) rather than assuming mainnet
- New enum variants break downstream exhaustive `match`es: `ChainType::Cardano`,
  `Curve::Ed25519Bip32`, `SignerError::{RpcError, UnsupportedChain}`, and
  `PayErrorCode::InvalidData`

Node and Python SDKs — arity changes only. Every new parameter is at the **end** of
the list, so existing positional calls are unaffected:

- `sign_message(wallet, chain, message, passphrase?, encoding?, index?, vaultPath?, address?)`
- `sign_typed_data(wallet, chain, typedDataJson, passphrase?, index?, vaultPath?, address?)`
- `import_wallet_private_key(…, secp256k1Key?, ed25519Key?, ed25519Bip32Key?)`

## [0.2.18] - 2026-03-09

### Fixed
- Python bindings packaging

### Changed
- Updated README and website copy

## [0.2.17] - 2026-03

### Added
- TON wallet upgraded to v5r1

### Fixed
- Clippy and formatting cleanup

## [0.2.16] - 2026-03

### Added
- TON chain support (Ed25519, raw/bounceable addresses)
- SDK documentation for Node.js and Python

### Fixed
- Wallet import bug
- CLI improvements

## [0.2.15] - 2026-02

### Changed
- Improved install script reliability
- Updated website and install instructions

## [0.2.14] - 2026-02

### Fixed
- Node.js publishing scripts
- Install script during release periods

## [0.2.10 - 0.2.12] - 2026-02

### Fixed
- Python package release process
- npm CI publishing
- Install script fixes

## [0.2.9] - 2026-01

### Changed
- Updated Python bindings and GitHub workflow

## [0.2.8] - 2026-01

### Fixed
- Release script fixes across all platforms

### Added
- Publish flows for Node.js and Python bindings

## [0.2.0] - 2025-12

### Added
- Universal wallet layer with multi-chain support
- Native Node.js bindings via NAPI-RS
- Native Python bindings via PyO3/Maturin
- Release workflow with cross-compiled CLI binaries
- Pre-signing policy engine
- Chain-agnostic addressing (CAIP-2/CAIP-10)
- Support for EVM, Solana, Bitcoin, Cosmos, and Tron

### Changed
- Replaced SDK clients with native FFI bindings
- Reorganized CLI command framework

## [0.1.0] - 2025-11

### Added
- Initial wallet specification
- CLI implementation
- HD key derivation and signing
- Vault storage format
- Website and documentation
