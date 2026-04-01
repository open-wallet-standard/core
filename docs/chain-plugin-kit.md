# Chain Plugin Kit

> Non-normative implementation design note for a contributor-focused scaffold command.

## 1. Problem

Adding a new supported chain currently requires contributors to understand and
update several manual sync points across the Rust workspace. Chain metadata,
CAIP mappings, derivation behavior, signer registration, tests, and docs are
spread across multiple files and crates.

That makes the first contribution harder than it needs to be and increases the
risk of partial or inconsistent changes.

## 2. Why This Matters For OWS's Supported-Chains / Multi-Chain Model

OWS is explicitly multi-chain. It uses CAIP identifiers, chain-family-aware
derivation rules, and chain-specific signing and serialization behavior.

Because supported chains are a core part of the OWS model, contributor
ergonomics matter. A clear scaffold reduces the time needed to add support for a
new chain and makes it easier to keep supported-chain changes consistent across
`ows-core`, `ows-signer`, `ows-lib`, CLI behavior, tests, and docs.

## 3. Goals

- Add a small contributor-oriented scaffold command to `ows-cli`
- Make the first step of adding a supported chain easier and more repeatable
- Generate a self-contained "Chain Plugin Kit" work area with the minimum files
  a contributor needs to start
- Keep the first PR dry-run-first and safe by default
- Reuse existing OWS terminology such as chain family, supported chain, CAIP,
  derivation path, and signer
- Keep the implementation merge-friendly for upstream review

## 4. Non-Goals

- No full runtime plugin loading
- No dynamic chain discovery at runtime
- No automatic edits to live integration files in `ows-core`, `ows-signer`, or
  `ows-lib`
- No support for introducing brand-new chain families in this PR
- No automatic RPC wiring, broadcast wiring, or bindings updates
- No cleanup of all existing manual-sync hazards in this PR

## 5. Recommended CLI Command Shape

```bash
ows dev scaffold-chain \
  --slug <slug> \
  --family <chain-type> \
  [--display-name <name>] \
  [--curve <secp256k1|ed25519>] \
  [--address-format <text>] \
  [--coin-type <u32>] \
  [--derivation-path <path>] \
  [--caip-namespace <token>] \
  [--caip-reference <token>] \
  [--output <path>] \
  [--write] \
  [--force]
```

Behavior:

- Dry run is the default
- `--write` creates the scaffold on disk
- `--family` must be an existing `ows_core::ChainType` and acts as the closest
  existing OWS family baseline for defaults
- optional placeholder flags override the generated defaults
- `--output` is optional and must stay inside the repository
- the command fails if the target exists unless `--force` is passed

Recommended default output:

```text
.ows-dev/chain-plugin-kit/<slug>/
```

## 6. Generated File/Folder Structure

```text
.ows-dev/
  chain-plugin-kit/
    <slug>/
      README.md
      CONTRIBUTOR_GUIDE.md
      chain-profile.toml
      caip-mapping.toml
      derivation-rules.toml
      sign.stub.rs
      serialize.stub.rs
      docs/
        supported-chain-entry.md
        implementation-checklist.md
        security-checklist.md
      test-vectors/
        README.md
        derivation.json
        sign-message.json
        tx-serialization.json
```

Purpose of generated files:

- `README.md`: short contributor-facing overview of the generated kit
- `CONTRIBUTOR_GUIDE.md`: step-by-step guide and likely OWS follow-up touchpoints
- `chain-profile.toml`: chain profile and address-format metadata
- `caip-mapping.toml`: canonical CAIP mapping and alias placeholders
- `derivation-rules.toml`: curve, coin type, and derivation placeholders
- `sign.stub.rs`: signing starter with TODOs
- `serialize.stub.rs`: signable-byte and serialization starter with TODOs
- `docs/supported-chain-entry.md`: supported-chain write-up skeleton
- `docs/implementation-checklist.md`: checklist for filling in the scaffold
- `docs/security-checklist.md`: security review checklist
- `test-vectors/README.md`: starter guidance for machine-readable vectors
- `test-vectors/*.json`: sample cases for derivation, message signing, and tx serialization

## 7. Validation Rules

- `slug` must be lowercase ASCII letters, numbers, and hyphens only
- `slug` must not be empty
- `slug` must not start or end with a hyphen
- `slug` must not contain repeated hyphens
- `display-name`, when provided, must be printable text without leading or
  trailing whitespace
- `family` must parse as an existing `ChainType`
- optional placeholder tokens such as `--caip-namespace` and
  `--caip-reference` must not contain whitespace or path separators
- `output` must resolve inside the repository root
- The command must fail if the target exists unless `--force` is passed
- The command must remain safe in dry-run mode and avoid filesystem writes

## 8. Testing Strategy

Keep tests focused in `ows-cli`.

Minimum test set:

- dry-run plan generation uses the expected default output path
- `--write` creates the expected scaffold file set
- template rendering includes `slug`, `display-name`, family, namespace, and
  derivation values
- output path validation rejects paths that escape the repository
- invalid `slug` values are rejected
- invalid display names are rejected
- an existing target requires `--force`
- `--force` replaces an existing scaffold deterministically

This PR does not need end-to-end runtime integration tests because it does not
change live chain support behavior.

## 9. Documentation Impact

This PR should update contributor-facing docs only.

Recommended documentation changes:

- add a short usage note to `CONTRIBUTING.md`
- rely on CLI help text for command discovery
- keep the note in `docs/chain-plugin-kit.md` as a non-normative implementation
  reference

This PR should not add a new numbered specification document.

## 10. Future Follow-Ups That Should NOT Be Included In This PR

- Automatically wiring generated data into `ows/crates/ows-core/src/chain.rs`
- Automatically generating signer files under `ows-signer/src/chains/`
- Automatically registering signers in `ows-signer/src/chains/mod.rs`
- Automatically updating `ALL_CHAIN_TYPES`, `KNOWN_CHAINS`, or default RPC maps
- Runtime plugin loading or external plugin discovery
- Scaffolding new chain families beyond existing `ChainType` variants
- Full conformance-vector ingestion or validation
- Spark / `ALL_CHAIN_TYPES` consistency cleanup
- Website docs integration for this design note

## Recommended First Code Change

Add a new `Dev` subcommand to `ows/crates/ows-cli/src/main.rs` with a
`ScaffoldChain` variant, then route it to a dedicated
`ows/crates/ows-cli/src/commands/dev.rs` module.
