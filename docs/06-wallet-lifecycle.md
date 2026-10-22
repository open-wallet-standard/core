# Wallet Lifecycle

> How wallets are created, imported, exported, backed up, recovered, and migrated.

## Creation

### Create from New Mnemonic

Generates a new BIP-39 mnemonic and derives initial accounts.

```bash
ows wallet create --name "agent-treasury" --chain evm
```

```typescript
const wallet = await ows.createWallet({
  name: "agent-treasury",
  chainType: "evm",
  chains: ["eip155:8453"],           // derive accounts for these chains
  accountCount: 1,                    // number of accounts per chain
  mnemonicStrength: 128               // 128 = 12 words, 256 = 24 words
});
// Returns: WalletDescriptor (never the mnemonic)
```

**Flow:**
1. Generate 128 or 256 bits of cryptographically secure randomness
2. Encode as BIP-39 mnemonic (12 or 24 words)
3. Derive master seed via PBKDF2
4. Derive accounts for each requested chain using BIP-44 paths
5. Encrypt mnemonic with vault passphrase (scrypt + AES-256-GCM)
6. Write encrypted wallet file to `~/.ows/wallets/<uuid>.json`
7. Wipe mnemonic, seed, and private keys from memory
8. Return only the `WalletDescriptor` (addresses, IDs, metadata)

The mnemonic is never returned to the caller. Only public information (addresses, IDs, metadata) is returned.

### Create from Existing Private Key

Import a raw private key (for single-chain wallets).

```bash
echo "<private-key>" | ows wallet import --name "imported" --chain evm --format raw
```

```typescript
const wallet = await ows.importWallet({
  name: "imported",
  chainType: "evm",
  chains: ["eip155:8453"],
  keyMaterial: privateKeyBytes,        // Uint8Array, wiped after import
  keyType: "private_key"
});
```

The key material is encrypted immediately and the input buffer is zeroed.

## Import

OWS supports importing from standard formats:

### Ethereum Keystore v3

```bash
ows wallet import --name "from-geth" --format keystore --file ~/keystore/UTC--2024-01-01T00-00-00.000Z--abc123
```

The importer reads the v3 JSON, wraps it in the OWS envelope, and optionally re-encrypts with the vault passphrase. If the keystore uses a different passphrase than the vault, the user is prompted for both.

### BIP-39 Mnemonic

```bash
ows wallet import --name "from-metamask" --format mnemonic --chain evm
# Prompts for mnemonic words interactively (never as a CLI argument)
```

The mnemonic is entered interactively to avoid shell history exposure. It is read via stdin, encrypted, and the input buffer is zeroed.

### WIF (Bitcoin Wallet Import Format)

```bash
echo "<wif-key>" | ows wallet import --name "btc-wallet" --format wif --chain bitcoin
```

### Solana Keypair JSON

```bash
ows wallet import --name "sol-wallet" --format solana-keypair --file ~/.config/solana/id.json
```

Reads the 64-byte keypair JSON array format used by the Solana CLI.

### Sui Keystore JSON

```bash
ows wallet import --name "sui-wallet" --format sui-keystore --file ~/.sui/sui_config/sui.keystore
```

Reads the base64-encoded keypair array format used by the Sui CLI (`sui keytool`).

## Export

Export operations extract key material for use with other wallet software. They require explicit confirmation and produce a visible security warning.

### Export Mnemonic

```bash
ows wallet export --id 3198bc9c-... --format mnemonic
# Displays the 12/24 word mnemonic on screen
# Warning: "This mnemonic provides full access to all accounts derived from this wallet."
```

```typescript
const mnemonic = await ows.exportWallet("3198bc9c-...", {
  format: "mnemonic"
});
// Returns string (12 or 24 words)
// Caller MUST handle securely and wipe from memory
```

### Export Keystore v3

```bash
ows wallet export --id 3198bc9c-... --format keystore --output ~/exported.json
```

Exports a standard Ethereum Keystore v3 file compatible with geth, MetaMask, etc. Only works for `key_type: "private_key"` or single-account EVM wallets.

### Export Private Key (Raw)

```bash
ows wallet export --id 3198bc9c-... --format raw --account eip155:8453:0xab16...
```

Exports a single account's private key as hex. For mnemonic-based wallets, the specific account's key is derived and exported (not the mnemonic itself).

## Backup

### Full Vault Backup

```bash
ows backup --output ~/ows-backup-2026-02-27.tar.gz.enc
```

Creates an encrypted archive of the entire `~/.ows/` directory:
1. Tar the vault directory (excluding `logs/` and `state/`)
2. Encrypt the tar with a backup passphrase (separate from vault passphrase)
3. Write to the output path

The backup is self-contained — it includes wallet files, policies, plugins, and config.

### Restore from Backup

```bash
ows restore --input ~/ows-backup-2026-02-27.tar.gz.enc
```

Decrypts and extracts the backup to `~/.ows/`. If the vault directory already exists, the user is prompted to merge or overwrite.

### Automated Backup

In `~/.ows/config.json`:

```json
{
  "backup": {
    "enabled": true,
    "schedule": "daily",
    "destination": "~/.ows/backups/",
    "retention": 30,
    "passphrase_env": "OWS_BACKUP_PASSPHRASE"
  }
}
```

## Recovery

### From Mnemonic

If the vault is lost but the mnemonic is available:

```bash
ows wallet recover --name "recovered" --chain evm --chains eip155:8453,eip155:1
# Prompts for mnemonic interactively
# Scans for accounts with balance using gap limit of 20
```

The recovery process:
1. Accept mnemonic interactively
2. Derive accounts using the chain's BIP-44 path, incrementing the index
3. For each derived address, query the RPC for balance or transaction history
4. Stop after 20 consecutive empty addresses (BIP-44 gap limit)
5. Create a new wallet file with all discovered accounts

### From Backup

See "Restore from Backup" above.

### From Keystore v3

See "Import > Ethereum Keystore v3" above.

## Deletion

```bash
ows wallet delete --id 3198bc9c-...
# Warning: "This will permanently delete the encrypted wallet file.
# Ensure you have exported the mnemonic or private key before proceeding."
# Requires --confirm flag or interactive confirmation
```

Deletion:
1. Verifies the wallet exists
2. Prompts for confirmation (unless `--confirm` is passed)
3. Securely overwrites the wallet file with random bytes before unlinking (to prevent recovery from disk)
4. Removes the wallet ID from the `wallet_ids` array of all API keys that reference it
5. Logs the deletion to the audit log

## Changing an Encryption Passphrase

The reference implementation can re-encrypt one existing wallet without exporting
its mnemonic/private keys or restoring it. Wallet IDs, addresses, account paths,
creation time, metadata and wallet-level extension fields remain unchanged.

```bash
ows wallet change-passphrase --wallet treasury
```

The CLI prompts for the current passphrase, then a new passphrase and confirmation
with terminal echo disabled. For noninteractive use, supply `OWS_PASSPHRASE`
(explicitly `""` for an initially empty passphrase) and `OWS_NEW_PASSPHRASE` through
your secret-management environment. Password arguments are intentionally absent.
The legacy `LWS_PASSPHRASE` is a fallback for the current password. Environment
variables are consumed, and password values are never written to the audit log.

The Rust API is `ows_lib::change_wallet_passphrase(name_or_id, old, new,
vault_path)`. Node exposes `changeWalletPassphrase` and Python exposes
`change_wallet_passphrase`. They return the unchanged public wallet information.
Both password parameters are explicit; whitespace and Unicode are preserved.
The new passphrase must be nonempty and cannot start with `ows_key_`, which the
signing API reserves for API tokens. The old owner passphrase authenticates the
operation; an API token is not a substitute.

Re-encryption uses fresh salt/IV values and preserves the original scrypt cost
parameters. Plaintext remains in zeroizing Rust memory; no plaintext backup is
created. Caller-owned JavaScript/Python strings cannot be erased by the binding.
Existing encrypted backups still use their original password. Changing this file
does not revoke API keys, alter their policy associations, terminate already
unlocked sessions, or change signing keys. Revoke API keys separately if access
must be removed, and update your encrypted backups after a successful change.

Stop other wallet writers while changing a password. Concurrent password changes
use a nonblocking OS lock; a busy operation returns an error. The persistent
`<wallet-file-stem>.passphrase.lock` file is not a backup and need not be removed;
the OS releases its lock on close or process exit. Rename/delete/import writers
do not share this lock. Changed snapshots are rejected before replacement, but
this is not a general concurrent-wallet transaction mechanism.

The replacement is written to a temporary file in the same directory, set to
0600 on Unix, synced and atomically renamed. Wrong passwords, invalid input and
pre-commit I/O failures leave the original wallet intact. Existing read-only
permissions are respected. Directory-entry durability during a sudden power loss
depends on the filesystem; this operation does not claim a power-loss recovery
protocol or a multi-wallet/vault-wide transaction.

## Key Rotation

OWS supports creating a new wallet and migrating assets from an old one:

```bash
ows wallet rotate --from old-wallet --to new-wallet --chain eip155:8453
```

This is a convenience operation that:
1. Creates a new wallet (or uses an existing one)
2. Queries balances on the old wallet
3. Constructs transfer transactions for all assets
4. Signs and sends using the old wallet
5. Verifies receipt on the new wallet

Key rotation does NOT re-encrypt the old wallet — it transfers assets to a new key.

## Wallet Discovery

For environments where multiple tools may create OWS wallets, a discovery mechanism helps avoid duplicate wallet creation:

```typescript
// Find wallets matching criteria
const wallets = await ows.discoverWallets({
  chainType: "evm",
  chainId: "eip155:8453",
  name: "agent-*",                    // glob pattern
  hasPolicy: true
});
```

The `ows wallet list` CLI command also supports filtering:

```bash
ows wallet list --chain evm --with-policy
ows wallet list --name "agent-*"
```

## Lifecycle State Diagram

```
                    ┌─────────┐
                    │ Create  │
                    │ Import  │
                    │ Recover │
                    └────┬────┘
                         │
                         ▼
                    ┌─────────┐
              ┌────▶│  Active │◀───────┐
              │     └────┬────┘        │
              │          │             │
         Unlock     Sign/Send    Attach Policy
              │          │             │
              │     ┌────▼────┐        │
              └─────│  Locked │        │
                    └────┬────┘        │
                         │             │
                    ┌────▼────┐   ┌────┴────┐
                    │ Export  │   │ Rotate  │
                    │ Backup │   └─────────┘
                    └────┬────┘
                         │
                    ┌────▼────┐
                    │ Delete  │
                    └─────────┘
```

## References

- [BIP-39: Mnemonic Generation](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Gap Limit](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [Ethereum Keystore v3](https://ethereum.org/developers/docs/data-structures-and-encoding/web3-secret-storage)
- [Solana CLI Keypair Format](https://docs.solanalabs.com/cli/wallets/file-system)
