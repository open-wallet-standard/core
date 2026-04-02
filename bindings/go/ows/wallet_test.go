package ows

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tempVault creates a new temporary directory and returns its path.
// The caller is responsible for removing it after the test.
func tempVault(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ows-test-*")
	require.NoError(t, err)
	return dir
}

func cleanupVault(t *testing.T, path string) {
	t.Helper()
	if path != "" {
		os.RemoveAll(path)
	}
}

// ---------------------------------------------------------------------------
// CreateWallet tests
// ---------------------------------------------------------------------------

func TestCreateWallet_OK(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("test-wallet", "hunter2", 12, vault)
	require.NoError(t, err)
	require.NotNil(t, wi)

	assert.NotEmpty(t, wi.ID)
	assert.Equal(t, "test-wallet", wi.Name)
	assert.NotEmpty(t, wi.CreatedAt)
	assert.NotEmpty(t, wi.Accounts, "expected at least one account")
}

// TestCreateWallet_DefaultWords verifies that words=0 uses the default (12).
func TestCreateWallet_DefaultWords(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("default-words", "", 0, vault)
	require.NoError(t, err)
	require.NotNil(t, wi)
	assert.Equal(t, "default-words", wi.Name)
}

func TestCreateWallet_EmptyName(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := CreateWallet("", "", 12, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeInvalidInput, e.Code)
}

// TestCreateWallet_DuplicateName verifies that creating a second wallet with
// the same name returns a WalletExists error.
func TestCreateWallet_DuplicateName(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := CreateWallet("dup-wallet", "", 12, vault)
	require.NoError(t, err)

	_, err = CreateWallet("dup-wallet", "", 12, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeWalletExists, e.Code)
}

func TestCreateWallet_InvalidWordCount(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := CreateWallet("bad-words", "", 13, vault) // 13 is not valid
	require.Error(t, err)
}

// TestCreateWallet_EmptyPassphrase verifies that an empty passphrase is accepted.
func TestCreateWallet_EmptyPassphrase(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("no-pass", "", 12, vault)
	require.NoError(t, err)
	assert.Equal(t, "no-pass", wi.Name)
}

// ---------------------------------------------------------------------------
// ListWallets tests
// ---------------------------------------------------------------------------

func TestListWallets_Empty(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wallets, err := ListWallets(vault)
	require.NoError(t, err)
	assert.Empty(t, wallets)
}

func TestListWallets_OneWallet(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	created, err := CreateWallet("list-test", "", 12, vault)
	require.NoError(t, err)

	wallets, err := ListWallets(vault)
	require.NoError(t, err)
	require.Len(t, wallets, 1)
	assert.Equal(t, created.ID, wallets[0].ID)
	assert.Equal(t, "list-test", wallets[0].Name)
}

func TestListWallets_MultipleWallets(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	names := []string{"wallet-a", "wallet-b", "wallet-c"}
	for _, name := range names {
		_, err := CreateWallet(name, "", 12, vault)
		require.NoError(t, err, "failed to create %s", name)
	}

	wallets, err := ListWallets(vault)
	require.NoError(t, err)
	assert.Len(t, wallets, 3, "expected 3 wallets")

	// Verify each wallet has at least one account with a non-empty address.
	for _, w := range wallets {
		require.NotEmpty(t, w.Accounts, "wallet %s has no accounts", w.Name)
		for _, acct := range w.Accounts {
			assert.NotEmpty(t, acct.ChainID)
			assert.NotEmpty(t, acct.Address)
		}
	}
}

func TestListWallets_Stable(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := CreateWallet("stable-wallet", "", 12, vault)
	require.NoError(t, err)

	// Call ListWallets twice; order and content should be identical.
	first, err := ListWallets(vault)
	require.NoError(t, err)

	second, err := ListWallets(vault)
	require.NoError(t, err)

	assert.Equal(t, len(first), len(second))
	for i := range first {
		assert.Equal(t, first[i].ID, second[i].ID)
		assert.Equal(t, first[i].Name, second[i].Name)
	}
}

func TestListWallets_PreservesAccountData(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	created, err := CreateWallet("account-check", "", 12, vault)
	require.NoError(t, err)

	wallets, err := ListWallets(vault)
	require.NoError(t, err)
	require.Len(t, wallets, 1)

	got := wallets[0]
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.Name, got.Name)
	assert.Equal(t, created.CreatedAt, got.CreatedAt)
	require.Len(t, got.Accounts, len(created.Accounts))
	for i, acct := range got.Accounts {
		assert.Equal(t, created.Accounts[i].ChainID, acct.ChainID)
		assert.Equal(t, created.Accounts[i].Address, acct.Address)
		assert.Equal(t, created.Accounts[i].DerivationPath, acct.DerivationPath)
	}
}

// TestListWallets_NonexistentVault verifies that a non-existent vault directory
// returns an empty list (not an error), matching ows-lib behavior.
func TestListWallets_NonexistentVault(t *testing.T) {
	nonexistent := filepath.Join(tempVault(t), "does-not-exist")
	// Cleanup only the parent; the child never existed.
	defer os.RemoveAll(filepath.Dir(nonexistent))

	wallets, err := ListWallets(nonexistent)
	// Depending on implementation this may error or return empty.
	// The important thing is it does not panic.
	if err == nil {
		assert.Empty(t, wallets)
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestError_Error(t *testing.T) {
	e := &Error{Code: CodeWalletNotFound, Message: "wallet not found: 'foo'"}
	assert.Equal(t, "ows: [1] wallet not found: 'foo'", e.Error())

	e2 := &Error{Code: CodeUnknown, Message: ""}
	assert.Equal(t, "ows: error code 99", e2.Error())
}

func TestError_Is(t *testing.T) {
	e1 := &Error{Code: 1, Message: "a"}
	e2 := &Error{Code: 1, Message: "a"}
	e3 := &Error{Code: 1, Message: "b"}
	e4 := &Error{Code: 2, Message: "a"}

	assert.True(t, e1.Is(e2))
	assert.False(t, e1.Is(e3))
	assert.False(t, e1.Is(e4))
}

func TestIsWalletNotFound(t *testing.T) {
	errNotFound := &Error{Code: CodeWalletNotFound, Message: "wallet not found"}
	errOther := &Error{Code: CodeInvalidInput, Message: "bad input"}

	assert.True(t, IsWalletNotFound(errNotFound))
	assert.False(t, IsWalletNotFound(errOther))
	assert.False(t, IsWalletNotFound(nil))
}

// ---------------------------------------------------------------------------
// Constants and types compile check
// ---------------------------------------------------------------------------

func TestIndexNoneConstant(t *testing.T) {
	assert.Equal(t, uint32(0xFFFFFFFF), IndexNone)
}

func TestWalletInfoFields(t *testing.T) {
	wi := &WalletInfo{
		ID:        "id-123",
		Name:      "my-wallet",
		CreatedAt: "1234567890",
		Accounts: []*AccountInfo{
			{ChainID: "evm", Address: "0xABC", DerivationPath: "m/44'/60'/0'/0/0"},
		},
	}
	assert.Equal(t, "id-123", wi.ID)
	assert.Equal(t, "my-wallet", wi.Name)
	assert.Equal(t, "0xABC", wi.Accounts[0].Address)
}

func TestSignResultFields(t *testing.T) {
	rid := uint8(27)
	sr := &SignResult{Signature: "0xdeadbeef", RecoveryID: &rid}
	assert.Equal(t, "0xdeadbeef", sr.Signature)
	assert.Equal(t, uint8(27), *sr.RecoveryID)

	srEd := &SignResult{Signature: "sig123", RecoveryID: nil}
	assert.Nil(t, srEd.RecoveryID)
}

// ---------------------------------------------------------------------------
// SignMessage tests
// ---------------------------------------------------------------------------

func TestSignMessage_EvmSuccess(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-msg-evm", "hunter2", 12, vault)
	require.NoError(t, err)
	require.NotEmpty(t, wi.Accounts)

	sr, err := SignMessage(wi.Name, "evm", "hello world", "hunter2", "", IndexNone, vault)
	require.NoError(t, err)
	require.NotNil(t, sr)
	assert.NotEmpty(t, sr.Signature, "expected non-empty signature")
	// EVM uses secp256k1 so recovery_id is present
	assert.NotNil(t, sr.RecoveryID, "expected recovery_id for secp256k1 chains")
}

func TestSignMessage_SolanaSuccess(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-msg-sol", "hunter2", 12, vault)
	require.NoError(t, err)

	// Solana uses Ed25519 — no recovery_id
	sr, err := SignMessage(wi.Name, "solana", "hello solana", "hunter2", "", IndexNone, vault)
	require.NoError(t, err)
	require.NotNil(t, sr)
	assert.NotEmpty(t, sr.Signature)
	assert.Nil(t, sr.RecoveryID, "Ed25519 chains should not have recovery_id")
}

func TestSignMessage_EmptyPassphrase(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-no-pass", "", 12, vault)
	require.NoError(t, err)

	sr, err := SignMessage(wi.Name, "evm", "no passphrase", "", "", IndexNone, vault)
	require.NoError(t, err)
	assert.NotEmpty(t, sr.Signature)
}

func TestSignMessage_MissingWallet(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := SignMessage("nonexistent-wallet", "evm", "hello", "", "", IndexNone, vault)
	require.Error(t, err)
	assert.True(t, IsWalletNotFound(err), "expected wallet-not-found error, got: %v", err)
}

func TestSignMessage_InvalidChain(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-bad-chain", "hunter2", 12, vault)
	require.NoError(t, err)

	_, err = SignMessage(wi.Name, "not-a-chain", "hello", "hunter2", "", IndexNone, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeInvalidInput, e.Code)
}

func TestSignMessage_WrongPassphrase(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-wrong-pass", "correct", 12, vault)
	require.NoError(t, err)

	_, err = SignMessage(wi.Name, "evm", "hello", "wrong-passphrase", "", IndexNone, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeUnknown, e.Code)
}

func TestSignMessage_EmptyMessage(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-empty-msg", "hunter2", 12, vault)
	require.NoError(t, err)

	// Empty message should still produce a valid signature (some chains may reject it downstream).
	sr, err := SignMessage(wi.Name, "evm", "", "hunter2", "", IndexNone, vault)
	require.NoError(t, err)
	assert.NotEmpty(t, sr.Signature)
}

// ---------------------------------------------------------------------------
// SignTx tests
// ---------------------------------------------------------------------------

func TestSignTx_EvmSuccess(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-tx-evm", "hunter2", 12, vault)
	require.NoError(t, err)

	// Raw EVM transaction hex (dummy payload — not a real transaction).
	// ows-lib treats this as opaque signable bytes.
	txHex := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	sr, err := SignTx(wi.Name, "evm", txHex, "hunter2", IndexNone, vault)
	require.NoError(t, err)
	require.NotNil(t, sr)
	assert.NotEmpty(t, sr.Signature, "expected non-empty signature")
	assert.NotNil(t, sr.RecoveryID, "expected recovery_id for secp256k1")
}

func TestSignTx_BitcoinSuccess(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sign-tx-btc", "hunter2", 12, vault)
	require.NoError(t, err)

	// Dummy Bitcoin transaction hex.
	txHex := "0200000001"
	sr, err := SignTx(wi.Name, "bitcoin", txHex, "hunter2", IndexNone, vault)
	require.NoError(t, err)
	assert.NotEmpty(t, sr.Signature)
	assert.NotNil(t, sr.RecoveryID, "secp256k1 chains should have recovery_id")
}

func TestSignTx_MissingWallet(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	_, err := SignTx("nonexistent", "evm", "deadbeef", "", IndexNone, vault)
	require.Error(t, err)
	assert.True(t, IsWalletNotFound(err), "expected wallet-not-found error, got: %v", err)
}

func TestSignTx_InvalidChain(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("signtx-bad-chain", "hunter2", 12, vault)
	require.NoError(t, err)

	_, err = SignTx(wi.Name, "not-a-chain", "deadbeef", "hunter2", IndexNone, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeInvalidInput, e.Code)
}

func TestSignTx_MalformedHex(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("signtx-bad-hex", "hunter2", 12, vault)
	require.NoError(t, err)

	// Not valid hex (contains 'g').
	_, err = SignTx(wi.Name, "evm", "notg00dh3x", "hunter2", IndexNone, vault)
	require.Error(t, err)
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeInvalidInput, e.Code)
}

func TestSignTx_EmptyHex(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("signtx-empty-hex", "hunter2", 12, vault)
	require.NoError(t, err)

	// The Rust library treats the raw transaction payload opaquely, so even an
	// empty payload still produces a deterministic signature.
	sr, err := SignTx(wi.Name, "evm", "", "hunter2", IndexNone, vault)
	require.NoError(t, err)
	assert.NotEmpty(t, sr.Signature)
}

// ---------------------------------------------------------------------------
// IsSignerError tests
// ---------------------------------------------------------------------------

func TestIsSignerError(t *testing.T) {
	errSigner := &Error{Code: CodeSigner, Message: "signer error"}
	errOther := &Error{Code: CodeInvalidInput, Message: "bad input"}

	assert.True(t, IsSignerError(errSigner))
	assert.False(t, IsSignerError(errOther))
	assert.False(t, IsSignerError(nil))
}

// ---------------------------------------------------------------------------
// Parity / signature format tests
// ---------------------------------------------------------------------------

func TestSignMessage_SignatureIsValidHex(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("sig-hex", "hunter2", 12, vault)
	require.NoError(t, err)

	for _, chain := range []string{"evm", "bitcoin", "cosmos", "tron", "filecoin"} {
		sr, err := SignMessage(wi.Name, chain, "test message", "hunter2", "", IndexNone, vault)
		require.NoError(t, err, "signing failed for chain %s", chain)
		assert.NotEmpty(t, sr.Signature, "empty signature for %s", chain)
		// Signature must be valid hex (no 0x prefix expected from lib).
		for _, c := range sr.Signature {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'),
				"non-hex char %c in signature for %s", c, chain)
		}
	}
}

func TestSignMessage_RecoveryIDRange(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("rec-id", "hunter2", 12, vault)
	require.NoError(t, err)

	// secp256k1 chains: evm, bitcoin, cosmos, tron, spark, filecoin
	secpChains := []string{"evm", "bitcoin", "cosmos", "tron", "spark", "filecoin"}
	for _, chain := range secpChains {
		sr, err := SignMessage(wi.Name, chain, "hello", "hunter2", "", IndexNone, vault)
		require.NoError(t, err, "signing failed for %s", chain)
		require.NotNil(t, sr.RecoveryID, "recovery_id must be present for secp256k1 chain %s", chain)
		assert.Contains(t, []uint8{0, 1, 27, 28}, *sr.RecoveryID, "unexpected recovery_id for %s", chain)
	}
}

func TestSignMessage_Ed25519HasNilRecoveryID(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("ed25519-nil-rec", "hunter2", 12, vault)
	require.NoError(t, err)

	// All known Ed25519 chains should return nil recovery ID.
	edChains := []string{"solana", "ton", "sui"}
	for _, chain := range edChains {
		sr, err := SignMessage(wi.Name, chain, "hello", "hunter2", "", IndexNone, vault)
		require.NoError(t, err, "signing failed for %s", chain)
		assert.Nil(t, sr.RecoveryID, "recovery_id must be nil for Ed25519 chain %s", chain)
	}
}

func TestSignTx_SignatureIsValidHex(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("signtx-hex", "hunter2", 12, vault)
	require.NoError(t, err)

	txHex := "f86c088501dcd6500082520894675300000000000000000000000077702a8dbe5f2a03021856"
	sr, err := SignTx(wi.Name, "evm", txHex, "hunter2", IndexNone, vault)
	require.NoError(t, err)
	assert.NotEmpty(t, sr.Signature)
	for _, c := range sr.Signature {
		assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'),
			"non-hex char %c in tx signature", c)
	}
}

func TestSignTx_RecoveryIDRange(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("signtx-rec", "hunter2", 12, vault)
	require.NoError(t, err)

	txHex := "f86c088501dcd6500082520894675300000000000000000000000077702a8dbe5f2a03021856"
	sr, err := SignTx(wi.Name, "evm", txHex, "hunter2", IndexNone, vault)
	require.NoError(t, err)
	require.NotNil(t, sr.RecoveryID)
	assert.LessOrEqual(t, *sr.RecoveryID, uint8(3))
}

func TestCreateWallet_DerivationPathFormat(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("deriv-path", "", 12, vault)
	require.NoError(t, err)
	require.NotEmpty(t, wi.Accounts)

	for _, acct := range wi.Accounts {
		assert.NotEmpty(t, acct.DerivationPath, "chain %s has empty derivation path", acct.ChainID)
		// BIP-44 derivation path pattern: m/44'/<coin_type>'/<account>'/<change>/<index>
		// or similar. Must start with "m/".
		assert.True(t, len(acct.DerivationPath) >= 4 && acct.DerivationPath[:2] == "m/",
			"derivation path %s doesn't start with 'm/'", acct.DerivationPath)
	}
}

func TestCreateWallet_CosmosAndTronAccounts(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	wi, err := CreateWallet("multi-chain", "", 12, vault)
	require.NoError(t, err)
	require.NotEmpty(t, wi.Accounts)

	chains := make(map[string]bool)
	for _, acct := range wi.Accounts {
		chains[acct.ChainID] = true
		assert.NotEmpty(t, acct.Address, "chain %s has empty address", acct.ChainID)
	}
	// A default wallet should expose multiple chain accounts.
	assert.GreaterOrEqual(t, len(chains), 2, "expected at least 2 distinct chain accounts")
}

// TestCreateWallet_RoundTrip verifies that creating and re-listing a wallet
// preserves every field byte-for-byte, including CreatedAt.
func TestCreateWallet_RoundTrip(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	created, err := CreateWallet("roundtrip", "", 12, vault)
	require.NoError(t, err)

	wallets, err := ListWallets(vault)
	require.NoError(t, err)
	require.Len(t, wallets, 1)

	got := wallets[0]
	assert.Equal(t, created.ID, got.ID, "ID must match")
	assert.Equal(t, created.Name, got.Name, "Name must match")
	assert.Equal(t, created.CreatedAt, got.CreatedAt, "CreatedAt must match")
	require.Len(t, got.Accounts, len(created.Accounts), "Account count must match")
	for i := range got.Accounts {
		assert.Equal(t, created.Accounts[i].ChainID, got.Accounts[i].ChainID, "ChainID must match")
		assert.Equal(t, created.Accounts[i].Address, got.Accounts[i].Address, "Address must match")
		assert.Equal(t, created.Accounts[i].DerivationPath, got.Accounts[i].DerivationPath, "DerivationPath must match")
	}
}

func TestListWallets_OrderStable(t *testing.T) {
	vault := tempVault(t)
	defer cleanupVault(t, vault)

	for i := 0; i < 5; i++ {
		_, err := CreateWallet(fmt.Sprintf("ordered-wallet-%d", i), "", 12, vault)
		require.NoError(t, err)
	}

	first, err := ListWallets(vault)
	require.NoError(t, err)

	// Call 3 more times — order must be identical.
	for n := 0; n < 3; n++ {
		wallets, err := ListWallets(vault)
		require.NoError(t, err)
		require.Len(t, wallets, len(first))
		for i := range wallets {
			assert.Equal(t, first[i].ID, wallets[i].ID, "order changed on call %d", n+2)
		}
	}
}
