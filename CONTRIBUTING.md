# Contributing to OWS

Thanks for your interest in contributing to the Open Wallet Standard! This guide will help you get started.

## Development Setup

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Node.js](https://nodejs.org/) >= 20 (for Node bindings)
- [Python](https://python.org/) >= 3.9 + [Maturin](https://www.maturin.rs/) (for Python bindings)

### Building from Source

```bash
# Clone the repo
git clone https://github.com/open-wallet-standard/core.git
cd core

# Build the Rust workspace
cd ows && cargo build --workspace --release

# Build Node bindings
cd bindings/node && npm install && npx napi build --platform --release

# Build Python bindings
cd bindings/python && maturin develop --release
```

### Running Tests

```bash
# Rust tests
cd ows && cargo test --workspace

# Node tests
cd bindings/node && npm test
```

### Code Formatting

```bash
cd ows && cargo fmt --all      # Format Rust code
cd ows && cargo clippy --workspace -- -D warnings  # Lint
```

## Making Changes

1. **Fork** the repo and create a branch from `main`.
2. **Make your changes.** Keep commits focused and use [conventional commit](https://www.conventionalcommits.org/) messages (e.g., `feat:`, `fix:`, `chore:`).
3. **Test.** Ensure `cargo test --workspace` passes and `cargo clippy` is clean.
4. **Open a PR** against `main` with a clear description of what changed and why.

### Chain Contributor Kit

If you are adding support for a new chain, start from the repository root with:

```bash
cd ows
cargo run -p ows-cli -- dev scaffold-chain --slug my-chain --family evm
```

That command performs a dry run and shows the files it would create under:

```text
.ows-dev/chain-plugin-kit/<slug>/
```

To create the scaffold on disk, re-run with `--write`.

Choose `--family` as the closest existing OWS family baseline for derivation
and signing defaults.

The first scaffold PR is intentionally conservative: it produces a self-contained
contributor kit and checklist without modifying runtime chain integration files
for you.

## Pull Request Guidelines

- Keep PRs small and focused — one logical change per PR.
- Update documentation if your change affects the public API or CLI.
- Add tests for new functionality.
- Ensure CI passes before requesting review.

## Project Structure

```
core/
├── ows/crates/
│   ├── ows-core/      # Types, CAIP parsing, errors
│   ├── ows-signer/    # HD derivation, signing, address generation
│   ├── ows-lib/       # FFI interface for language bindings
│   └── ows-cli/       # CLI tool
├── bindings/
│   ├── node/          # Node.js NAPI bindings
│   └── python/        # Python (PyO3/Maturin) bindings
├── docs/              # Specification documents
└── website/           # Static site (openwallet.sh)
```

## Reporting Bugs

Open a [GitHub Issue](https://github.com/open-wallet-standard/core/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- OS, Rust version, and OWS version (`ows --version`)

## Questions?

Open a [discussion](https://github.com/open-wallet-standard/core/discussions) or an issue — we're happy to help.
