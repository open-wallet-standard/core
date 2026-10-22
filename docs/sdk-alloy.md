# Alloy integration

The `ows-alloy` crate implements Alloy's asynchronous and synchronous signing
traits over the existing OWS library. Use it with `EthereumWallet` to sign from a
stored EVM account without exporting private keys.

See the [crate README](../ows/crates/ows-alloy/README.md) for installation from
source, a compiling example, supported account paths, chain-ID handling,
API-token policy routing, credential lifetime and runtime requirements.

This is an OWS-side integration. It does not add native `cast` or `forge` CLI
support. Node and Python bindings remain independent of Alloy.
