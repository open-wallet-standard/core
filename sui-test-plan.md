# Sui Support Test Plan

## How to run

```bash
# All tests (should be 260 total: 50 + 46 + 164)
cargo test

# Sui-specific unit tests only
cargo test -p ows-signer sui::

# Integration tests that now include Sui
cargo test -p ows-lib
```

## 1. Chain registry (`ows-core`)

| Test | What it checks |
|---|---|
| `test_serde_all_variants` | `"sui"` round-trips through serde |
| `test_namespace_mapping` | `ChainType::Sui.namespace() == "sui"` |
| `test_coin_type_mapping` | `ChainType::Sui.default_coin_type() == 784` |
| `test_from_namespace` | `ChainType::from_namespace("sui") == Some(Sui)` |
| `test_all_chain_types` | `ALL_CHAIN_TYPES.len() == 8` (was 7) |

## 2. SuiSigner unit tests (`ows-signer::chains::sui`)

**Properties & paths:**
| Test | What it checks |
|---|---|
| `test_chain_properties` | `chain_type=Sui`, `curve=Ed25519`, `coin_type=784` |
| `test_derivation_path` | `m/44'/784'/{i}'/0'/0'` — all 5 levels hardened |

**Address derivation:**
| Test | What it checks |
|---|---|
| `test_address_derivation_format` | Starts with `0x`, length 66, deterministic |
| `test_address_derivation_correctness` | Matches manual BLAKE2b-256(`0x00 \|\| pubkey`) computation |

**Signing:**
| Test | What it checks |
|---|---|
| `test_sign_raw_ed25519` | Raw `sign()` produces 64-byte sig, `recovery_id=None`, `public_key=None`, verifies with ed25519-dalek |
| `test_sign_transaction_intent_digest` | `sign_transaction()` produces sig over `BLAKE2b-256([0,0,0] \|\| bcs_tx)`, populates `public_key` (32 bytes) |
| `test_sign_message_personal` | `sign_message()` uses intent scope 3 (`[3,0,0]`), BCS-serializes message before hashing, sig verifies |
| `test_deterministic_signing` | Same key + same input = same signature |

**Wire format & encoding:**
| Test | What it checks |
|---|---|
| `test_wire_signature_format` | `encode_signed_transaction` output = `tx_bytes \|\| wire_sig(97)`, wire sig = `0x00 \|\| sig(64) \|\| pubkey(32)` |
| `test_encode_roundtrip_split` | Split at `len - 97` recovers original tx bytes and 97-byte sig |
| `test_full_pipeline` | `extract_signable → sign_transaction → encode → split → verify` end-to-end; signature over intent digest verifies using pubkey extracted from wire sig |

**Error handling:**
| Test | What it checks |
|---|---|
| `test_invalid_key` | 16-byte key rejected by both `derive_address` and `sign` |

**BCS helper:**
| Test | What it checks |
|---|---|
| `test_bcs_serialize_bytes` | ULEB128 length prefix: single-byte (5), two-byte (128), zero-length |

## 3. Integration tests (`ows-lib`)

These existing tests were updated to include `"sui"` in their chain lists:

| Test | What it checks for Sui |
|---|---|
| `derive_address_all_chains` | Mnemonic → Sui address derivation succeeds, non-empty |
| `mnemonic_wallet_sign_message_all_chains` | `sign_message("sui", ...)` succeeds from a mnemonic wallet |
| `mnemonic_wallet_sign_tx_all_chains` | `sign_transaction("sui", ...)` succeeds (uses generic tx hex) |

## 4. Config

| Test | What it checks |
|---|---|
| `test_load_or_default_nonexistent` | Default RPC count is 14 (includes `sui:mainnet`) |

## 5. Manual / not yet covered

These are things the automated tests don't cover that you may want to verify separately:

- **HD derivation from mnemonic**: The full `mnemonic → SLIP-10 → m/44'/784'/0'/0'/0' → privkey → address` path runs through existing HD infrastructure. The integration tests exercise it, but we don't compare against an external Sui SDK test vector. If you have a known mnemonic/address pair from the Sui TypeScript SDK or `sui keytool`, that would be a strong cross-validation.
- **broadcast_sui**: The function is wired up but not tested (requires a live RPC). The split logic (`len - 97`) is validated by `test_encode_roundtrip_split`. To test broadcast shape, you could mock or inspect the JSON body — it should be `{"jsonrpc":"2.0","method":"sui_executeTransactionBlock","params":[base64_tx,[base64_sig],null,null],"id":1}`.
- **Existing chain regression**: All 8 existing signers had `public_key: None` added to their `SignOutput` construction. The full test suite (164 signer tests + 46 lib tests) passes, confirming no regressions.
