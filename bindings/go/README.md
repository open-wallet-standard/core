# Go Bindings for Open Wallet Standard (OWS) v1

Minimal Go bindings via cgo + Rust FFI.

## Build Prerequisites

1. **Rust toolchain** (stable)
2. **Go 1.21+**

## Build Steps

The Go package is at `bindings/go/ows/` (import path `github.com/open-wallet-standard/core/bindings/go/ows`).
The Rust FFI crate is at `bindings/go/` (crate name `ows-go`).

```bash
# Clone the repository
git clone https://github.com/open-wallet-standard/core.git
cd core

# 1. Build the Rust FFI library
cd bindings/go
cargo build --release -p ows-go

# 2. Build the Go package
# Linux/macOS
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$(pwd)/target/release -lows_go"
export LD_LIBRARY_PATH="$(pwd)/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"   # Linux
export DYLD_LIBRARY_PATH="$(pwd)/target/release${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" # macOS
go build ./ows/...

# Windows (PowerShell)
$release = (Resolve-Path .\target\release).Path
$env:CGO_ENABLED="1"
$env:CGO_LDFLAGS="-L$($release -replace '\\','/') -lows_go"
$env:PATH="$release;$env:PATH"
go build ./ows/...

# 3. Run tests (from bindings/go, after building the Rust library)
go test -v ./ows/...

# 4. Run the example program (from bindings/go)
go run ./examples/demo.go
```

## Public API (v1 scope)

### Wallet Operations

```go
// CreateWallet creates a new wallet with addresses for all supported chains.
// words: 12 or 24 (use 0 for default 12).
// vaultPath: "" uses default ~/.ows; pass a temp path for isolated tests.
wi, err := ows.CreateWallet("my-wallet", "hunter2", 12, vaultPath)
wi.Name, wi.ID, wi.Accounts[].ChainID, wi.Accounts[].Address

// ListWallets returns all wallets in the vault.
wallets, err := ows.ListWallets(vaultPath)
```

### Signing Operations

```go
// SignMessage signs a UTF-8 message on behalf of a wallet.
// chain: "evm", "solana", "bitcoin", "cosmos", "tron", "ton", "sui", "spark", "filecoin"
// encoding: "" or "utf8" for UTF-8 input, or "hex" for hex-decoded bytes
// index: use ows.IndexNone to default to account 0.
// Returns SignResult { Signature: string, RecoveryID: *uint8 (nil for Ed25519 chains) }
sr, err := ows.SignMessage("my-wallet", "evm", "hello world", "hunter2", "", ows.IndexNone, vaultPath)
sr.Signature  // hex-encoded signature
sr.RecoveryID // present for secp256k1 chains (evm/btc/cosmos/tron/spark/filecoin); nil for Ed25519 (solana/ton/sui)

// SignTx signs a raw transaction.
// txHex: hex-encoded transaction bytes (0x prefix optional).
// Returns the same SignResult shape as SignMessage.
sr, err := ows.SignTx("my-wallet", "evm", "f86c08...", "hunter2", ows.IndexNone, vaultPath)
```

### Error Handling

```go
var err error

// Check for specific error conditions.
if ows.IsWalletNotFound(err) {
    // wallet does not exist
}
if ows.IsSignerError(err) {
    // signer-layer failure
}
```

### Encoding Expectations

| Function | Input format | Notes |
|---|---|---|
| `SignMessage` | UTF-8 string or hex-decoded bytes | Use `""`/`"utf8"` for UTF-8 input or `"hex"` for hex input. |
| `SignTx` | Hex-encoded bytes | No 0x prefix required. Chain determines transaction format. |

### Returned Signature Fields

`SignResult` returned by both `SignMessage` and `SignTx`:

```go
type SignResult struct {
    Signature  string  // hex-encoded signature
    RecoveryID *uint8 // present for secp256k1 chains; nil for Ed25519
}
```

## v1 Scope

This package exposes only:

- `CreateWallet`, `ListWallets` (wallet operations)
- `SignMessage`, `SignTx` (signing operations)
- `WalletInfo`, `AccountInfo`, `SignResult`, `Error` types
- `IndexNone` sentinel constant
- `IsWalletNotFound`, `IsSignerError` helpers

**Explicitly deferred to v2**: `ImportWallet`, `DeleteWallet`, `ExportWallet`, `RenameWallet`, `GetWallet`, `SignTypedData`, `SignAndSend`, policy management, API key management.

## Examples

A runnable demo is provided at `examples/demo.go`. Build the Rust library first, then run from the `bindings/go` directory:

```bash
# From the bindings/go directory
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$(pwd)/target/release -lows_go"
go run ./examples/demo.go
```

## Troubleshooting

**"library not found" during `go build`**

Set `CGO_LDFLAGS` to the path containing `libows_go.so` (Linux), `libows_go.dylib` (macOS), or `ows_go.dll`/`ows_go.dll.lib` (Windows):

```bash
export CGO_LDFLAGS="-L$(pwd)/target/release -lows_go"
```

On Windows, also add `target/release` to `PATH` before `go test` or `go run` so the DLL can be loaded at runtime.

**"ows-go library not found" on macOS after update**

Clear the Cargo build cache and rebuild:

```bash
cargo build --release -p ows-go
```

**Tests fail with "wallet not found"**

Tests use isolated temporary vaults and clean up after themselves. If a test process is killed, stale temp directories may remain — these are safe to delete manually.

**Panic or segfault in Rust FFI**

Ensure the Rust cdylib and Go package are rebuilt from the same commit. Mixing a stale `.so`/`.dylib`/`.dll` with a newer Go package can cause ABI mismatches.

## Memory Model

All strings passed to Rust are copied; Rust allocations are freed by the Go package internally. Callers do not need to manage FFI memory.

## License

MIT
