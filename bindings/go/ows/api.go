package ows

/*
#cgo LDFLAGS: -lows_go

#include <stdint.h>
#include <stdlib.h>

// Rust FFI — all have C linkage via #[no_mangle] pub extern "C"
extern char* ows_go_create_wallet(const char* name, const char* passphrase, uint32_t words, const char* vault_path);
extern char* ows_go_list_wallets(const char* vault_path);
extern char* ows_go_sign_message(const char* wallet, const char* chain, const char* message, const char* passphrase, const char* encoding, uint32_t index, const char* vault_path);
extern char* ows_go_sign_transaction(const char* wallet, const char* chain, const char* tx_hex, const char* passphrase, uint32_t index, const char* vault_path);
extern void  ows_go_free_string(char* s);
extern int32_t ows_go_get_last_error_code(void);
extern const char* ows_go_get_last_error(void);
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"
)

// IndexNone is the sentinel for "use default account index (0)".
const IndexNone = ^uint32(0)

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

// Error codes matching the Rust library.
const (
	CodeOK              = 0
	CodeWalletNotFound  = 1
	CodeWalletAmbiguous = 2
	CodeWalletExists    = 3
	CodeInvalidInput    = 4
	CodeBroadcastFailed = 5
	CodeCrypto          = 6
	CodeSigner          = 7
	CodeMnemonic        = 8
	CodeHD              = 9
	CodeCore            = 10
	CodeIO              = 11
	CodeJSON            = 12
	CodeUnknown         = 99
)

// Error is returned by all package functions on failure.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("ows: [%d] %s", e.Code, e.Message)
	}
	return fmt.Sprintf("ows: error code %d", e.Code)
}

// Is reports whether err is the same as e (code+message match).
func (e *Error) Is(err error) bool {
	var o *Error
	if !errors.As(err, &o) {
		return false
	}
	return e.Code == o.Code && e.Message == o.Message
}

// IsWalletNotFound reports whether err indicates a wallet was not found.
func IsWalletNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == CodeWalletNotFound
}

// IsSignerError reports whether err indicates a signing operation failed
// (e.g. invalid payload, unsupported chain, key not found).
func IsSignerError(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == CodeSigner
}

// ---------------------------------------------------------------------------
// Internal FFI helpers
// ---------------------------------------------------------------------------

// lastError reads the thread-local error state set by the last Rust call.
func lastError() *Error {
	code := int(C.ows_go_get_last_error_code())
	if code == CodeOK {
		return nil
	}
	return &Error{Code: code, Message: C.GoString(C.ows_go_get_last_error())}
}

// goFree frees a C string allocated by Go via C.CString (use stdlib free).
func goFree(c *C.char) {
	C.free(unsafe.Pointer(c))
}

// rustFree frees a C string allocated by Rust (use ows_go_free_string).
func rustFree(c *C.char) {
	if c != nil {
		C.ows_go_free_string(c)
	}
}

// ---------------------------------------------------------------------------
// Wallet operations (v1)
// ---------------------------------------------------------------------------

// CreateWallet creates a new wallet with derived addresses for all supported chains.
// Pass "" for vaultPath to use the default vault (~/.ows).
//
// Example:
//
//	wi, err := ows.CreateWallet("my-wallet", "hunter2", 12, "")
func CreateWallet(name, passphrase string, words uint, vaultPath string) (*WalletInfo, error) {
	if name == "" {
		return nil, &Error{Code: CodeInvalidInput, Message: "wallet name cannot be empty"}
	}

	cname := C.CString(name)
	cpass := C.CString(passphrase)
	cvault := C.CString(vaultPath)
	defer goFree(cname)
	defer goFree(cpass)
	defer goFree(cvault)

	res := C.ows_go_create_wallet(cname, cpass, C.uint(words), cvault)
	if res == nil {
		return nil, lastError()
	}
	defer rustFree(res)

	var wi WalletInfo
	if err := json.Unmarshal([]byte(C.GoString(res)), &wi); err != nil {
		return nil, fmt.Errorf("ows: parse WalletInfo: %w", err)
	}
	return &wi, nil
}

// ListWallets returns all wallets in the vault.
// Pass "" for vaultPath to use the default vault (~/.ows).
//
// Example:
//
//	wallets, err := ows.ListWallets("")
func ListWallets(vaultPath string) ([]*WalletInfo, error) {
	cvault := C.CString(vaultPath)
	defer goFree(cvault)

	res := C.ows_go_list_wallets(cvault)
	if res == nil {
		return nil, lastError()
	}
	defer rustFree(res)

	var wallets []*WalletInfo
	if err := json.Unmarshal([]byte(C.GoString(res)), &wallets); err != nil {
		return nil, fmt.Errorf("ows: parse WalletInfo slice: %w", err)
	}
	return wallets, nil
}

// ---------------------------------------------------------------------------
// Signing operations (v1)
// ---------------------------------------------------------------------------

// SignMessage signs a UTF-8 message on behalf of a wallet.
// chain is the chain identifier (e.g. "evm", "solana", "bitcoin").
// encoding may be "" for auto-detect. Use IndexNone for index to default to 0.
// Pass "" for vaultPath to use the default vault (~/.ows).
//
// Example:
//
//	sig, err := ows.SignMessage("my-wallet", "evm", "hello world", "hunter2", "", ows.IndexNone, "")
func SignMessage(wallet, chain, message, passphrase, encoding string, index uint32, vaultPath string) (*SignResult, error) {
	if encoding == "" {
		encoding = "utf8"
	}

	cwallet := C.CString(wallet)
	cchain := C.CString(chain)
	cmessage := C.CString(message)
	cpass := C.CString(passphrase)
	cenc := C.CString(encoding)
	cvault := C.CString(vaultPath)
	defer func() {
		goFree(cwallet)
		goFree(cchain)
		goFree(cmessage)
		goFree(cpass)
		goFree(cenc)
		goFree(cvault)
	}()

	res := C.ows_go_sign_message(cwallet, cchain, cmessage, cpass, cenc, C.uint(index), cvault)
	if res == nil {
		return nil, lastError()
	}
	defer rustFree(res)

	var sr SignResult
	if err := json.Unmarshal([]byte(C.GoString(res)), &sr); err != nil {
		return nil, fmt.Errorf("ows: parse SignResult: %w", err)
	}
	return &sr, nil
}

// SignTx signs a raw transaction (hex-encoded bytes).
// Use IndexNone for index to default to 0.
//
// Example:
//
//	sig, err := ows.SignTx("my-wallet", "evm", "deadbeef...", "hunter2", ows.IndexNone, "")
func SignTx(wallet, chain, txHex, passphrase string, index uint32, vaultPath string) (*SignResult, error) {
	cwallet := C.CString(wallet)
	cchain := C.CString(chain)
	ctxhex := C.CString(txHex)
	cpass := C.CString(passphrase)
	cvault := C.CString(vaultPath)
	defer func() {
		goFree(cwallet)
		goFree(cchain)
		goFree(ctxhex)
		goFree(cpass)
		goFree(cvault)
	}()

	res := C.ows_go_sign_transaction(cwallet, cchain, ctxhex, cpass, C.uint(index), cvault)
	if res == nil {
		return nil, lastError()
	}
	defer rustFree(res)

	var sr SignResult
	if err := json.Unmarshal([]byte(C.GoString(res)), &sr); err != nil {
		return nil, fmt.Errorf("ows: parse SignResult: %w", err)
	}
	return &sr, nil
}
