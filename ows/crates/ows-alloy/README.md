# OWS Alloy signer

`ows-alloy` connects a stored OWS EVM account to Alloy's `Signer`, `SignerSync`,
`TxSigner` and `TxSignerSync` traits. It can be passed to `EthereumWallet`.
Private keys stay inside OWS; the adapter receives signatures and public wallet
metadata. It does not add a native OWS flag to Foundry's `cast` or `forge`.

## Use from this checkout

```toml
[dependencies]
ows-alloy = { path = "path/to/core/ows/crates/ows-alloy" }
alloy-network = "2"
alloy-signer = { version = "2", features = ["eip712"] }
tokio = { version = "1", features = ["rt", "macros"] }
```

The workspace lockfile selects Alloy 2.1.1, compatible with the pinned Rust
1.94.0 toolchain. Newer Alloy 2.x releases can require newer Rust. This new crate
is separate from `ows-lib`, so the Node/Python bindings do not acquire Alloy
dependencies. No published `ows-alloy` release is assumed by these instructions.

```rust,no_run
use alloy_network::EthereumWallet;
use alloy_signer::Signer;
use ows_alloy::OwsSigner;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Supply an owner password or scoped API token through your secret manager.
    let credential = std::env::var("OWS_PASSPHRASE")?;
    let signer = OwsSigner::new("treasury", credential, 1, None)?;
    let signature = signer.sign_message(b"hello").await?;
    let wallet = EthereumWallet::new(signer);
    // Pass `wallet` to an Alloy ProviderBuilder's .wallet(wallet) method.
    // The adapter itself never broadcasts transactions.
    # let _ = (signature, wallet);
    Ok(())
}
```

The stored EVM account selects the address and derivation index. Standard
`m/44'/60'/0'/0/i` mnemonic paths and imported private-key accounts are supported;
other paths are rejected. To use another index, import a wallet with that index
through OWS first. The wallet is pinned by ID, so renaming it does not redirect
the signer. The vault path is resolved at construction. Construction reads
metadata; a wrong credential fails when signing. Returned signatures are checked
against the stored address before they are exposed to the caller.

## Policy routing and chains

Each method invokes the matching OWS operation, including for API tokens:

| Alloy operation | OWS operation / policy request type |
| --- | --- |
| Raw hash | `sign_hash` |
| EIP-191 message, including binary input | `sign_message` |
| Static or dynamic EIP-712 data | `sign_typed_data` |
| Transaction | `sign_transaction` |

Transactions reach policies as their complete unsigned signing bytes. EIP-712
data reaches policies as named JSON fields, including generic `SolStruct` values
that do not implement `serde::Serialize`. ABI conversion is checked against
Alloy's original EIP-712 hash. No typed data or transaction is silently routed
through a raw-hash call by the adapter's implementations.

The JSON sent to OWS normalizes message integers to 32-byte, `0x`-prefixed hex
strings (signed integers use two's complement). The domain chain ID is a decimal
string, and the domain type schema is derived from Alloy's actual domain fields.
This preserves the full 256-bit range across the two libraries' JSON
decoders. Named fields and types remain available; policies must parse these
integer encodings. Undeclared JSON message properties are not signed fields and
are omitted during normalization. Multidimensional arrays retain their nested
shape. Domain-only requests (`primaryType: "EIP712Domain"`) sign only the domain
separator, matching Alloy, and pass an empty message object to policies.

The constructor's nonzero chain ID is the policy context for hashes/messages/
typed data, and the initial transaction chain setting. Typed-data domain chain
IDs, when present, must match this policy context. `Signer::set_chain_id` changes
the transaction fill/check setting only; it does not change the constructor's
policy context for chainless operations. With `Some(id)`, transactions with a
missing chain ID receive it and mismatches fail. With `None`, transactions must
already have their own nonzero chain ID. Transaction policies always receive
that actual chain ID. Chain-zero and unprotected legacy transactions are rejected.

Raw hashes have no recoverable message/transaction semantics. Policies requiring
structured input must explicitly deny `sign_hash`. Alloy trait wrappers or other
libraries may compute a hash themselves and call that operation, including some
generic typed-data defaults on wrapper types; the adapter cannot reconstruct
data from a digest. Use the concrete `OwsSigner` or its dynamic typed-data method
when the full typed-data context is required. Owner credentials continue to
bypass policies by OWS design. This integration adds no cumulative spend ledger.

## Runtime and credential lifetime

Synchronous methods block for decryption and policy execution. Async methods
require a Tokio runtime and use its blocking pool, including on a current-thread
runtime. They return an error if no runtime is available. Cancelling an async
call does not stop an already-running blocking signing operation; it does not
submit a transaction. Configure Tokio's blocking pool appropriately for your
workload rather than running unbounded signing requests.

Signer clones share one zeroizing credential buffer. It is cleared when the last
clone/in-flight worker releases it. `Debug` redacts it. Caller-owned copies,
including the original environment variable, remain the caller's responsibility.
OWS authenticates and rechecks API-key scope, revocation and policies on each
operation. The adapter does not retain a decrypted key.

## Validation

Run `cargo test -p ows-alloy` from `ows/`. Tests use temporary wallets, offline
signatures and Alloy's local signer as a reference; they make no live payments.
They cover legacy, EIP-2930/1559/4844/7702 transaction signing, EthereumWallet
envelopes, binary messages, nested EIP-712 values, account indices, chain
mismatches, credentials, revocation, policy contexts and Tokio behavior.

This is the OWS-side integration for
[issue #223](https://github.com/open-wallet-standard/core/issues/223).
Native Foundry CLI integration requires a separate Foundry-side change.
