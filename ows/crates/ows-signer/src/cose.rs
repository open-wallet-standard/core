//! Minimal COSE (RFC 8152) encoding for CIP-8 message signing.
//!
//! Only implements the subset Cardano wallets exchange: a `COSE_Sign1` over an
//! Ed25519 signature carrying the signer's address in the protected header, the
//! `Sig_structure` that signature is computed over, and the `COSE_Key` that
//! publishes the verifying key. Nothing here parses COSE — OWS only ever emits it.
//!
//! OWS encodes this itself rather than depending on Emurgo's
//! `emurgo-cardano-message-signing`, which filled the role first. That crate has had
//! exactly one release, and it pins `wasm-bindgen` to `=0.2.92`; Midnight's ledger
//! stack floors the same crate at `=0.2.100` through `reqwest` and `js-sys`. Both
//! pins sit on the same semver-compatible `0.2` line, so Cargo resolves one version
//! of `wasm-bindgen` for the whole graph and no version satisfies both requirements
//! — the two chains could not otherwise share a lockfile. The encoding below
//! reproduces that crate's output byte for byte, against the vectors it produced.
//!
//! The encoding is deterministic: every map is definite-length, the header labels
//! are written in the fixed order below, and no field is optional. Wallets and
//! dapps compare these bytes, so the layout is fixed by
//! [`crate::chains::cardano`]'s signing tests rather than left to a serializer.

/// COSE header label 1, `alg` (RFC 8152 §3.1).
const HEADER_LABEL_ALG: u64 = 1;
/// COSE key parameter 1, `kty` (RFC 8152 §7.1).
const KEY_LABEL_KTY: u64 = 1;
/// COSE key parameter 3, `alg`.
const KEY_LABEL_ALG: u64 = 3;
/// COSE key parameter -1, `crv` (RFC 8152 §13.1).
const KEY_LABEL_CRV: i64 = -1;
/// COSE key parameter -2, `x` — the public key for an OKP.
const KEY_LABEL_X: i64 = -2;

/// `alg` value for pure EdDSA (RFC 8152 §8.2), the algorithm Cardano signs with.
const ALG_EDDSA: i64 = -8;
/// `kty` value for an octet key pair (RFC 8152 §13).
const KTY_OKP: u64 = 1;
/// `crv` value for Ed25519 (RFC 8152 §13.2).
const CRV_ED25519: u64 = 6;

/// CIP-8's own protected header, carrying the address the message is signed for.
/// Not a COSE label: CIP-8 keys it by the text string `"address"`.
const HEADER_LABEL_ADDRESS: &str = "address";
/// CIP-8's `hashed` unprotected header. OWS signs the payload as given, so it is
/// always `false`; a verifier reads it to know the payload is not a blake2b digest.
const HEADER_LABEL_HASHED: &str = "hashed";

/// The `Sig_structure` context string for a single-signer `COSE_Sign1` (RFC 8152 §4.4).
const SIG_CONTEXT_SIGNATURE1: &str = "Signature1";

// CBOR major types (RFC 8949 §3.1).
const MAJOR_UINT: u8 = 0;
const MAJOR_NEGINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

/// CBOR `false` — major type 7, simple value 20.
const CBOR_FALSE: u8 = 0xf4;

/// Write a CBOR item head: the major type in the top three bits, then the
/// argument in the shortest form that holds it.
fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let ib = major << 5;
    match arg {
        0..=23 => out.push(ib | arg as u8),
        24..=0xff => {
            out.push(ib | 24);
            out.push(arg as u8);
        }
        0x100..=0xffff => {
            out.push(ib | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(ib | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(ib | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn write_uint(out: &mut Vec<u8>, value: u64) {
    write_head(out, MAJOR_UINT, value);
}

/// CBOR stores a negative integer as `-1 - n`, so -8 is major type 1 argument 7.
fn write_negint(out: &mut Vec<u8>, value: i64) {
    debug_assert!(value < 0, "write_negint takes a negative value");
    write_head(out, MAJOR_NEGINT, (-1 - value) as u64);
}

fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_head(out, MAJOR_BYTES, value.len() as u64);
    out.extend_from_slice(value);
}

fn write_text(out: &mut Vec<u8>, value: &str) {
    write_head(out, MAJOR_TEXT, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

/// Build the serialized protected header map `{1: -8, "address": <address>}`.
///
/// It is serialized once and then carried as an opaque byte string, because the
/// `Sig_structure` and the `COSE_Sign1` must agree on it byte for byte — a
/// verifier re-signs the bytes it was given, not a re-encoding of their meaning.
fn protected_header(address: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_head(&mut out, MAJOR_MAP, 2);
    write_uint(&mut out, HEADER_LABEL_ALG);
    write_negint(&mut out, ALG_EDDSA);
    write_text(&mut out, HEADER_LABEL_ADDRESS);
    write_bytes(&mut out, address);
    out
}

/// A `COSE_Sign1` under construction: the protected header is fixed at
/// construction so the bytes signed and the bytes published cannot drift apart.
pub struct Sign1Builder {
    protected: Vec<u8>,
    payload: Vec<u8>,
}

impl Sign1Builder {
    /// Sign `payload` as `address`. Both are copied; neither is hashed.
    pub fn new(address: &[u8], payload: &[u8]) -> Self {
        Self {
            protected: protected_header(address),
            payload: payload.to_vec(),
        }
    }

    /// The `Sig_structure` to sign: `["Signature1", protected, external_aad, payload]`
    /// (RFC 8152 §4.4). CIP-8 supplies no external AAD, so that slot is an empty
    /// byte string rather than omitted.
    pub fn data_to_sign(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_head(&mut out, MAJOR_ARRAY, 4);
        write_text(&mut out, SIG_CONTEXT_SIGNATURE1);
        write_bytes(&mut out, &self.protected);
        write_bytes(&mut out, &[]);
        write_bytes(&mut out, &self.payload);
        out
    }

    /// The finished `COSE_Sign1`: `[protected, unprotected, payload, signature]`.
    /// Emitted untagged — CIP-30 `signData` returns the bare array, not tag 18.
    pub fn build(&self, signature: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_head(&mut out, MAJOR_ARRAY, 4);
        write_bytes(&mut out, &self.protected);
        write_head(&mut out, MAJOR_MAP, 1);
        write_text(&mut out, HEADER_LABEL_HASHED);
        out.push(CBOR_FALSE);
        write_bytes(&mut out, &self.payload);
        write_bytes(&mut out, signature);
        out
    }
}

/// The `COSE_Key` publishing an Ed25519 verifying key:
/// `{1: 1, 3: -8, -1: 6, -2: <public key>}`.
pub fn ed25519_public_key(public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_head(&mut out, MAJOR_MAP, 4);
    write_uint(&mut out, KEY_LABEL_KTY);
    write_uint(&mut out, KTY_OKP);
    write_uint(&mut out, KEY_LABEL_ALG);
    write_negint(&mut out, ALG_EDDSA);
    write_negint(&mut out, KEY_LABEL_CRV);
    write_uint(&mut out, CRV_ED25519);
    write_negint(&mut out, KEY_LABEL_X);
    write_bytes(&mut out, public_key);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enterprise-address vector from the Cardano signing tests, which was
    /// produced by `emurgo-cardano-message-signing` before OWS encoded COSE itself.
    const ADDRESS: &str = "6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303";
    const PUBLIC_KEY: &str = "65a7f55e5fb6964610d0e220c37aadd502041e8f90a86b82c46e531a69612128";
    const SIGNATURE: &str = "1bb30176a6f48c3eefd4f659afd29c98e4668e4d5676474b7e4497e960e6a8e79860fd3bdb41093e448fc62aa74291490b683adb579e6a3e17a89d0b329ea70f";

    fn builder() -> Sign1Builder {
        Sign1Builder::new(
            &hex::decode(ADDRESS).unwrap(),
            &hex::decode("cafe").unwrap(),
        )
    }

    #[test]
    fn head_uses_the_shortest_argument_form() {
        let mut out = Vec::new();
        write_uint(&mut out, 23);
        write_uint(&mut out, 24);
        write_uint(&mut out, 0x100);
        write_uint(&mut out, 0x1_0000);
        write_uint(&mut out, 0x1_0000_0000);
        assert_eq!(hex::encode(out), "1718181901001a000100001b0000000100000000");
    }

    #[test]
    fn negative_integers_encode_as_minus_one_minus_n() {
        let mut out = Vec::new();
        write_negint(&mut out, -1);
        write_negint(&mut out, -8);
        write_negint(&mut out, -25);
        assert_eq!(hex::encode(out), "20273818");
    }

    #[test]
    fn protected_header_carries_eddsa_and_the_address() {
        assert_eq!(
            hex::encode(protected_header(&hex::decode(ADDRESS).unwrap())),
            "a201276761646472657373581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303"
        );
    }

    #[test]
    fn sig_structure_matches_the_reference_encoding() {
        assert_eq!(
            hex::encode(builder().data_to_sign()),
            "846a5369676e617475726531582aa201276761646472657373581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed03034042cafe"
        );
    }

    #[test]
    fn cose_sign1_matches_the_reference_encoding() {
        assert_eq!(
            hex::encode(builder().build(&hex::decode(SIGNATURE).unwrap())),
            format!("84582aa201276761646472657373581d6106094a93d88f9d832697898a387d44ecf2265570a6c92718d8ed0303a166686173686564f442cafe5840{SIGNATURE}")
        );
    }

    #[test]
    fn cose_key_matches_the_reference_encoding() {
        assert_eq!(
            hex::encode(ed25519_public_key(&hex::decode(PUBLIC_KEY).unwrap())),
            format!("a4010103272006215820{PUBLIC_KEY}")
        );
    }
}
