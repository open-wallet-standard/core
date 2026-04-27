# `ows doctor` Design Note

> Internal design document for the `ows doctor` diagnostic command.

## Overview

`ows doctor` is a read-only diagnostic command that inspects the local OWS installation and vault health. It does not mutate, repair, or modify any files.

## 1. CLI Position

`ows doctor` is a **top-level command** in `Commands`, positioned alongside `Update` and `Uninstall`:

```rust
/// In main.rs
enum Commands {
    // ... existing ...
    Doctor,
}
```

Handler dispatches to `commands::doctor::run()`.

## 2. V1 Checks

| Check ID | Name | Description |
|----------|------|-------------|
| `vault_path` | Vault Path Resolution | Vault path derived from `Config::default()` |
| `vault_exists` | Vault Existence | Whether `~/.ows` directory exists |
| `wallets_dir` | Wallets Directory | Whether `wallets/` subdirectory exists and is readable |
| `config_parse` | Config Parse | Whether `config.json` exists and parses as `Config` |
| `wallet_files` | Wallet Files | Enumerate all `.json` files in `wallets/`, parse each as `EncryptedWallet` |
| `key_files` | Key Files | Enumerate all `.json` files in `keys/`, parse each as `ApiKeyFile` |
| `policy_files` | Policy Files | Enumerate all `.json` files in `policies/`, parse each as `Policy` |
| `vault_permissions` | Vault Permissions | Check directory and file permissions (Unix only, skip on Windows) |
| `runtime_deps` | Runtime Dependencies | Check for OpenSSL via `pkg-config` (Unix only) |
| `home_env` | HOME Environment | Whether `HOME` env var is set |

## 3. Internal Data Model

```rust
/// Status of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorStatus {
    Pass,      // Check succeeded
    Warn,      // Check passed but with concerns
    Fail,      // Check failed
    Skip,      // Check skipped (not applicable, e.g., no wallets yet)
}

/// A single diagnostic check result.
#[derive(Debug)]
pub struct DoctorFinding {
    pub id: &'static str,
    pub status: DoctorStatus,
    pub message: String,
    pub remediation: Option<String>,
}

/// Aggregated diagnostic report.
#[derive(Debug, Default)]
pub struct DoctorReport {
    pub findings: Vec<DoctorFinding>,
}
```

**Key design decisions:**
- `Skip` is distinct from `Pass` to avoid alarming users about normal states (e.g., no wallets yet)
- `remediation` is `Option<String>` — present for `Warn` and `Fail`, absent for `Pass` and `Skip`
- No severity enumeration (OK/WARN/ERROR/INFO) — V1 uses `Pass/Warn/Fail/Skip` only
- Report is just a collection of findings; grouping/sorting happens at display time

## 4. Warning/Error Taxonomy

V1 uses a **4-state model**:

| State | Meaning | Exit Code Impact |
|-------|---------|------------------|
| `Pass` | Check succeeded, no issues | Continue (0) |
| `Skip` | Check not applicable (e.g., no wallets) | Continue (0) |
| `Warn` | Minor concern detected | Continue (0) |
| `Fail` | Critical issue detected | Exit (1) |

**Rules:**
- If **any** `Fail` exists → exit code 1
- Otherwise → exit code 0

## 5. Output Shape (Human-Readable)

```
OWS Doctor
==========

[Pass]  vault_path    Vault resolved to ~/.ows
[Pass]  vault_exists  ~/.ows exists
[Pass]  wallets_dir   wallets/ present (2 wallets found)
[Pass]  config_parse  config.json valid (15 RPC endpoints)
[Pass]  policy_files  policies/ valid (1 policy)
[Skip]  key_files     keys/ not present
[Pass]  vault_perms   Permissions correct
[Pass]  home_env      HOME is set
[Pass]  runtime_deps  OpenSSL available

Summary: 7 passed, 0 warnings, 0 failed, 2 skipped
```

**With warnings:**
```
[Pass]  vault_path    Vault resolved to ~/.ows
[Pass]  vault_exists  ~/.ows exists
[Pass]  wallets_dir   wallets/ present (2 wallets found)
[Pass]  config_parse  config.json valid
[Warn]  vault_perms   ~/.ows has mode 0755, expected 0700
         → Run: chmod 700 ~/.ows

Summary: 4 passed, 1 warning, 0 failed, 0 skipped
```

**With failures:**
```
[Fail]  wallet_files  wallet-abc.json: JSON parse error at line 3
         → Backup and recreate the wallet

Summary: 3 passed, 0 warnings, 1 failed, 0 skipped
```

**Key output rules:**
- No emoji in the check list (emoji only in summary banner)
- Remediation on the line below, indented with `→ `
- No color codes (not a terminal UI feature)
- Grouped by status in output: Fail first, then Warn, then Pass, then Skip

## 6. Testing Plan

| Test | Scope |
|------|-------|
| `test_doctor_report_default` | Empty vault — all findings are Skip except vault_path/vault_exists |
| `test_doctor_report_missing_home` | HOME unset — `home_env` returns Warn |
| `test_doctor_report_permission_warning` | Vault dir mode 0755 — `vault_perms` returns Warn |
| `test_doctor_report_wallet_corrupted` | Invalid JSON in wallet file — `wallet_files` returns Fail |
| `test_doctor_report_multiple_findings` | Several findings at once — summary counts are correct |
| `test_doctor_exit_code_pass` | All findings Pass/Skip → exit 0 |
| `test_doctor_exit_code_fail` | Any Fail → exit 1 |
| `test_doctor_exit_code_warn_only` | Warn only → exit 0 |

Tests live in `ows-cli/src/commands/doctor.rs` under `#[cfg(test)]`.

## 7. V1 Out of Scope

The following are explicitly **not** included in V1:

- **File repair or mutation** — no `chmod`, no backup, no auto-fix
- **Wallet balance or RPC connectivity checks** — network calls; out of scope for local diagnostics
- **Deterministic JSON output** — human-readable only in V1; structured output (e.g., `--json`) is V2
- **Per-wallet detailed report** — V1 shows counts only; individual wallet health is V2
- **Policy rule validation** — V1 checks file parseability only; rule evaluation is V2
- **Cross-vault migration checks** — no checking of `~/.lws` vs `~/.ows`
- **Dependency version checking** — `cargo`, `git`, Node.js version detection

## 8. File Changes Plan

| File | Change |
|------|--------|
| `ows/crates/ows-cli/src/commands/doctor.rs` | **New** — all diagnostic logic |
| `ows/crates/ows-cli/src/commands/mod.rs` | Add `pub mod doctor;` |
| `ows/crates/ows-cli/src/main.rs` | Add `Doctor` variant + handler |
| `docs/sdk-cli.md` | Add `### ows doctor` section under System Commands |

## 9. Crate Boundaries

```
ows-cli (command layer)
  └── calls: ows_lib::vault, ows_lib::policy_store
  └── calls: ows_core::Config, ows_core::EncryptedWallet, ows_core::Policy, ows_core::ApiKeyFile
  └── calls: ows_signer (no-op in doctor, just re-exports)

ows-lib (storage layer)
  └── vault.rs: resolve_vault_path(), wallets_dir(), list_encrypted_wallets()
  └── policy_store.rs: policies_dir(), list_policies()
  └── key_ops.rs: keys_dir() — NOT YET EXPOSED; may need to add

ows-core (types layer)
  └── Config, EncryptedWallet, Policy, ApiKeyFile
```

**Note:** `keys_dir()` is not currently exposed from `ows-lib`. It must be added to `ows-lib/src/vault.rs` and re-exported in `ows-lib/src/lib.rs` before `key_files` check can enumerate key files.

## 10. Implementation Phases

**Phase 1 (this PR):**
- Core model: `DoctorStatus`, `DoctorFinding`, `DoctorReport`
- All checks except `key_files`
- Human-readable output
- Unit tests
- Docs

**Phase 2 (future):**
- Add `keys_dir()` to `ows-lib`
- `key_files` check
- `--json` structured output flag

**Phase 3 (future):**
- Per-wallet detailed report
- Policy rule validation
