# 08 - Wallet Lifecycle

> How wallets are created, imported, exported, backed up, recovered, and migrated.

## Design Decision

**LWS defines a complete wallet lifecycle with explicit operations for creation, import (from existing standards), export (to portable formats), backup, and recovery. All lifecycle operations maintain the same key isolation guarantees as signing — private key material is handled exclusively inside the signing enclave.**

### Why Lifecycle Matters for Agent Wallets

Agent wallets have different lifecycle needs than human wallets:

| Concern | Human Wallet | Agent Wallet |
|---|---|---|
| Creation | Manual, infrequent | Automated, potentially frequent (per-agent or per-task) |
| Backup | User responsibility | Must be systematic and automated |
| Recovery | Seed phrase on paper | Must be programmatic |
| Migration | Rare (wallet switching) | Common (infra changes, key rotation) |
| Deletion | Rare | Regular (agent decommissioning) |

LWS must support both patterns.

## Creation

### Create from New Mnemonic

Generates a new BIP-39 mnemonic and derives initial accounts.

```bash
lws wallet create --name "agent-treasury" --chain evm
```

```typescript
const wallet = await lws.createWallet({
  name: "agent-treasury",
  chainType: "evm",
  chains: ["eip155:8453"],           // derive accounts for these chains
  accountCount: 1,                    // number of accounts per chain
  mnemonicStrength: 128               // 128 = 12 words, 256 = 24 words
});
// Returns: WalletDescriptor (never the mnemonic)
```

**Flow inside the enclave:**
1. Generate 128 or 256 bits of cryptographically secure randomness
2. Encode as BIP-39 mnemonic (12 or 24 words)
3. Derive master seed via PBKDF2
4. Derive accounts for each requested chain using BIP-44 paths
5. Encrypt mnemonic with vault passphrase (scrypt + AES-256-GCM)
6. Write encrypted wallet file to `~/.lws/wallets/<uuid>.json`
7. Wipe mnemonic, seed, and private keys from memory
8. Return only the `WalletDescriptor` (addresses, IDs, metadata)

The mnemonic NEVER leaves the enclave. The caller receives only public information.

### Create from Existing Private Key

Import a raw private key (for single-chain wallets).

```bash
echo "<private-key>" | lws wallet import --name "imported" --chain evm --format raw
```

```typescript
const wallet = await lws.importWallet({
  name: "imported",
  chainType: "evm",
  chains: ["eip155:8453"],
  keyMaterial: privateKeyBytes,        // Uint8Array, wiped after import
  keyType: "private_key"
});
```

The key material is passed directly to the enclave, encrypted, and the input buffer is zeroed.

## Import

LWS supports importing from standard formats:

### Ethereum Keystore v3

```bash
lws wallet import --name "from-geth" --format keystore --file ~/keystore/UTC--2024-01-01T00-00-00.000Z--abc123
```

The importer reads the v3 JSON, wraps it in the LWS envelope, and optionally re-encrypts with the vault passphrase. If the keystore uses a different passphrase than the vault, the user is prompted for both.

### BIP-39 Mnemonic

```bash
lws wallet import --name "from-metamask" --format mnemonic --chain evm
# Prompts for mnemonic words interactively (never as a CLI argument)
```

The mnemonic is entered interactively to avoid shell history exposure. It is passed directly to the enclave via stdin pipe.

### WIF (Bitcoin Wallet Import Format)

```bash
echo "<wif-key>" | lws wallet import --name "btc-wallet" --format wif --chain bitcoin
```

### Solana Keypair JSON

```bash
lws wallet import --name "sol-wallet" --format solana-keypair --file ~/.config/solana/id.json
```

Reads the 64-byte keypair JSON array format used by the Solana CLI.

## Export

Export operations extract key material for use with other wallet software. They require explicit confirmation and produce a visible security warning.

### Export Mnemonic

```bash
lws wallet export --id 3198bc9c-... --format mnemonic
# Displays the 12/24 word mnemonic on screen
# Warning: "This mnemonic provides full access to all accounts derived from this wallet."
```

```typescript
const mnemonic = await lws.exportWallet("3198bc9c-...", {
  format: "mnemonic"
});
// Returns string (12 or 24 words)
// Caller MUST handle securely and wipe from memory
```

### Export Keystore v3

```bash
lws wallet export --id 3198bc9c-... --format keystore --output ~/exported.json
```

Exports a standard Ethereum Keystore v3 file compatible with geth, MetaMask, etc. Only works for `key_type: "private_key"` or single-account EVM wallets.

### Export Private Key (Raw)

```bash
lws wallet export --id 3198bc9c-... --format raw --account eip155:8453:0xab16...
```

Exports a single account's private key as hex. For mnemonic-based wallets, the specific account's key is derived and exported (not the mnemonic itself).

## Backup

### Full Vault Backup

```bash
lws backup --output ~/lws-backup-2026-02-27.tar.gz.enc
```

Creates an encrypted archive of the entire `~/.lws/` directory:
1. Tar the vault directory (excluding `logs/` and `state/`)
2. Encrypt the tar with a backup passphrase (separate from vault passphrase)
3. Write to the output path

The backup is self-contained — it includes wallet files, policies, plugins, and config.

### Restore from Backup

```bash
lws restore --input ~/lws-backup-2026-02-27.tar.gz.enc
```

Decrypts and extracts the backup to `~/.lws/`. If the vault directory already exists, the user is prompted to merge or overwrite.

### Automated Backup

In `~/.lws/config.json`:

```json
{
  "backup": {
    "enabled": true,
    "schedule": "daily",
    "destination": "~/.lws/backups/",
    "retention": 30,
    "passphrase_env": "LWS_BACKUP_PASSPHRASE"
  }
}
```

## Recovery

### From Mnemonic

If the vault is lost but the mnemonic is available:

```bash
lws wallet recover --name "recovered" --chain evm --chains eip155:8453,eip155:1
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
lws wallet delete --id 3198bc9c-...
# Warning: "This will permanently delete the encrypted wallet file.
# Ensure you have exported the mnemonic or private key before proceeding."
# Requires --confirm flag or interactive confirmation
```

Deletion:
1. Verifies the wallet exists
2. Prompts for confirmation (unless `--confirm` is passed)
3. Securely overwrites the wallet file with random bytes before unlinking (to prevent recovery from disk)
4. Removes the wallet ID from any attached policy references
5. Logs the deletion to the audit log

## Key Rotation

LWS supports creating a new wallet and migrating assets from an old one:

```bash
lws wallet rotate --from old-wallet --to new-wallet --chain eip155:8453
```

This is a convenience operation that:
1. Creates a new wallet (or uses an existing one)
2. Queries balances on the old wallet
3. Constructs transfer transactions for all assets
4. Signs and sends using the old wallet
5. Verifies receipt on the new wallet

Key rotation does NOT re-encrypt the old wallet — it transfers assets to a new key.

## Wallet Discovery

For environments where multiple tools may create LWS wallets, a discovery mechanism helps avoid duplicate wallet creation:

```typescript
// Find wallets matching criteria
const wallets = await lws.discoverWallets({
  chainType: "evm",
  chainId: "eip155:8453",
  name: "agent-*",                    // glob pattern
  hasPolicy: true
});
```

The `lws wallet list` CLI command also supports filtering:

```bash
lws wallet list --chain evm --with-policy
lws wallet list --name "agent-*"
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
- [Privy: Key Export](https://docs.privy.io/wallets/overview)
- [W3C Universal Wallet: import/export](https://w3c-ccg.github.io/universal-wallet-interop-spec/)
- [Solana CLI Keypair Format](https://docs.solanalabs.com/cli/wallets/file-system)
