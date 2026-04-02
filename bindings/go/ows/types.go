package ows

// AccountInfo represents a single account within a wallet (one per chain family).
type AccountInfo struct {
	ChainID        string `json:"chain_id"`
	Address        string `json:"address"`
	DerivationPath string `json:"derivation_path"`
}

// WalletInfo represents a wallet returned by CreateWallet or ListWallets.
type WalletInfo struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Accounts  []*AccountInfo `json:"accounts"`
	CreatedAt string         `json:"created_at"`
}

// SignResult is returned by SignMessage and SignTx.
type SignResult struct {
	Signature  string `json:"signature"`
	RecoveryID *uint8 `json:"recovery_id"`
}
