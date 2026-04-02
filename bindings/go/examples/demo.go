//go:build ignore

// Demo program for the OWS Go binding.
//
// Build the Rust FFI library first:
//
//	cargo build --release -p ows-go
//
// Then run with CGO_LDFLAGS set:
//
//	# Linux/macOS
//	export CGO_ENABLED=1
//	export CGO_LDFLAGS="-L$(pwd)/target/release -lows_go"
//	go run ./examples/demo.go
//
//	# Windows (PowerShell)
//	$release = (Resolve-Path .\target\release).Path
//	$env:CGO_ENABLED="1"
//	$env:CGO_LDFLAGS="-L$($release -replace '\\','/') -lows_go"
//	$env:PATH="$release;$env:PATH"
//	go run .\examples\demo.go
//
// The demo creates a wallet in a temporary vault, signs a message and a
// transaction, then prints the results. No data is written to the default vault.

package main

import (
	"fmt"
	"os"

	ows "github.com/open-wallet-standard/core/bindings/go/ows"
)

func main() {
	// Use a temporary vault so this demo never touches the user's real vault.
	vault, err := os.MkdirTemp("", "ows-demo-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp vault: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(vault)

	// ── 1. Create a wallet ────────────────────────────────────────────────────
	fmt.Println("=== CreateWallet ===")
	wallet, err := ows.CreateWallet("demo-wallet", "hunter2", 12, vault)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CreateWallet failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created wallet %q (ID: %s)\n", wallet.Name, wallet.ID)
	fmt.Println("Accounts:")
	for _, acct := range wallet.Accounts {
		fmt.Printf("  chain=%s address=%s derivation=%s\n",
			acct.ChainID, acct.Address, acct.DerivationPath)
	}

	// ── 2. List wallets ───────────────────────────────────────────────────────
	fmt.Println("\n=== ListWallets ===")
	wallets, err := ows.ListWallets(vault)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListWallets failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d wallet(s)\n", len(wallets))
	for _, w := range wallets {
		fmt.Printf("  - %s (ID: %s)\n", w.Name, w.ID)
	}

	// ── 3. Sign a message (EVM) ───────────────────────────────────────────────
	fmt.Println("\n=== SignMessage (EVM) ===")
	sr, err := ows.SignMessage(
		wallet.Name,   // wallet name
		"evm",         // chain
		"hello world", // UTF-8 message
		"hunter2",     // passphrase
		"",            // encoding (auto-detect)
		ows.IndexNone, // use account index 0
		vault,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SignMessage failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Signature (hex): %s\n", sr.Signature)
	if sr.RecoveryID != nil {
		fmt.Printf("Recovery ID: %d\n", *sr.RecoveryID)
	} else {
		fmt.Println("Recovery ID: <nil> (Ed25519)")
	}

	// ── 4. Sign a raw transaction (EVM) ──────────────────────────────────────
	fmt.Println("\n=== SignTx (EVM) ===")
	// Raw EVM transaction hex (dummy payload — not a real transaction).
	txHex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	srTx, err := ows.SignTx(
		wallet.Name,   // wallet name
		"evm",         // chain
		txHex,         // hex-encoded transaction
		"hunter2",     // passphrase
		ows.IndexNone, // use account index 0
		vault,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SignTx failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Transaction signature (hex): %s\n", srTx.Signature)
	if srTx.RecoveryID != nil {
		fmt.Printf("Recovery ID: %d\n", *srTx.RecoveryID)
	}

	fmt.Println("\n=== Done ===")
}
