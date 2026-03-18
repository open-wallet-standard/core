# AGENTS.md

## Cursor Cloud specific instructions

### Overview

OWS (Open Wallet Standard) is a local-first, multi-chain crypto wallet library + CLI. No databases, no Docker, no external services required. Everything runs on the local filesystem (`~/.ows/wallets/`).

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Rust workspace | `ows/` | Core library + CLI (4 crates) |
| Node.js bindings | `bindings/node/` | NAPI native addon |
| Python bindings | `bindings/python/` | PyO3/Maturin extension |
| Website | `website/` | Static HTML docs |

### Rust toolchain

The VM ships with Rust 1.83, but the project requires a newer toolchain due to `clap` dependencies needing the `edition2024` Cargo feature. The update script handles `rustup update stable`. The rustup-managed `cargo` binary lives under `$RUSTUP_HOME/toolchains/stable-*/bin/` — if you get `edition2024` errors, ensure your `PATH` resolves the rustup-managed `cargo` (run `rustup which cargo` to verify).

### Key commands

Standard build/test/lint commands are documented in `CONTRIBUTING.md`. Quick reference:

- **Build:** `cd ows && cargo build --workspace`
- **Test:** `cd ows && cargo test --workspace`
- **Lint:** `cd ows && cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings`
- **Node build:** `cd bindings/node && npm install && npx napi build --platform --release --features fast-kdf`
- **Node test:** `cd bindings/node && npm test`
- **Python build:** `cd bindings/python && python3 -m venv .venv && source .venv/bin/activate && pip install maturin && maturin develop --release`
- **CLI run (dev):** `cd ows && cargo run --bin ows -- <subcommand>`

### Non-obvious notes

- The `fast-kdf` feature flag (available on Node bindings crate and Rust workspace) lowers scrypt iteration count for faster test execution. Always use `--features fast-kdf` when building for tests. The Python bindings crate does **not** have a `fast-kdf` feature.
- The Python module is `ows`, not `open_wallet_standard`. Import as `from ows import create_wallet`.
- The CLI binary is built from `ows/crates/ows-cli/`. Use `cargo run --bin ows` from the `ows/` directory to run it during development.
- CI checks (see `.github/workflows/ci.yml`): README generation check, `cargo fmt`, `cargo clippy`, `cargo test`, Node build + test.
