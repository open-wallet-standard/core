//! MIP-0005 offer files and MIP-0006 offer payloads, as `balanceSealedTransaction` maker inputs.
//!
//! An offer file is a proven, deliberately imbalanced Midnight `Transaction` shared as a bech32m string
//! under the `swapoffer` HRP. Decoded, it is the sealed maker offer the merge path completes. A MIP-0006
//! payload is what an offer indexer serves: the offer string plus the gives/wants it derived from it.

use std::collections::BTreeMap;

use bech32::Bech32m;
use midnight_base_crypto::signatures::Signature as MnSig;
use midnight_coin_structure::coin::TokenType as LedgerTokenType;
use midnight_ledger::structure::{ProofMarker, Transaction};
use midnight_serialize::{tagged_deserialize, tagged_serialize, Deserializable as _};
use midnight_storage::db::InMemoryDB;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use transient_crypto::commitment::PureGeneratorPedersen;

use super::build::err;
use super::is_sealed_maker_payload;

type TxSealed = Transaction<MnSig, ProofMarker, PureGeneratorPedersen, InMemoryDB>;

/// MIP-0005 human-readable part (`swapoffer1…` on the wire).
pub const SWAP_OFFER_HRP: &str = "swapoffer";

/// Whether `s` is a MIP-0005 offer string. bech32 also allows an all-uppercase string, so the HRP is
/// matched case-insensitively.
pub(super) fn is_swap_offer(s: &str) -> bool {
    s.get(..SWAP_OFFER_HRP.len() + 1)
        .is_some_and(|p| p.eq_ignore_ascii_case(&format!("{SWAP_OFFER_HRP}1")))
}

/// Decode a MIP-0005 `swapoffer1…` string into tagged transaction bytes, the form every other maker
/// input takes. MIP-0005 carries the ledger's serialization as-is; a payload written without the
/// ledger's tag is accepted too and re-tagged.
pub(super) fn decode_swap_offer(s: &str) -> Result<Vec<u8>, std::io::Error> {
    retag(swap_offer_bytes(s)?)
}

/// The bytes a `swapoffer1…` string carries, exactly as encoded: what MIP-0005's content address
/// (`offerId`) hashes.
///
/// The checksum is verified by driving the Bech32m engine directly: the crate's checked decoder caps a
/// string at 90 characters, which MIP-0005 forbids, and a proven offer runs to thousands.
fn swap_offer_bytes(s: &str) -> Result<Vec<u8>, std::io::Error> {
    use bech32::primitives::checksum;
    use bech32::primitives::decode::UncheckedHrpstring;
    use bech32::{Checksum, Fe32};

    let unchecked = UncheckedHrpstring::new(s.trim())
        .map_err(|e| err(format!("invalid swapoffer bech32: {e}")))?;
    if !unchecked
        .hrp()
        .as_str()
        .eq_ignore_ascii_case(SWAP_OFFER_HRP)
    {
        return Err(err(format!(
            "expected the swapoffer bech32 HRP, got {}",
            unchecked.hrp().as_str()
        )));
    }
    if unchecked.data_part_ascii().len() < Bech32m::CHECKSUM_LENGTH {
        return Err(err("invalid swapoffer bech32: data too short for checksum"));
    }
    let mut eng = checksum::Engine::<Bech32m>::new();
    eng.input_hrp(unchecked.hrp());
    for &b in unchecked.data_part_ascii() {
        eng.input_fe(Fe32::from_char_unchecked(b));
    }
    if eng.residue() != &Bech32m::TARGET_RESIDUE {
        return Err(err("invalid swapoffer bech32 checksum"));
    }
    Ok(unchecked.remove_checksum::<Bech32m>().byte_iter().collect())
}

fn retag(bytes: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    if bytes.starts_with(b"midnight:") {
        return Ok(bytes);
    }
    let tx = TxSealed::deserialize(&mut bytes.as_slice(), 0).map_err(|e| {
        err(format!(
            "swapoffer payload is not a sealed transaction: {e}"
        ))
    })?;
    let mut tagged = Vec::new();
    tagged_serialize(&tx, &mut tagged).map_err(|e| err(format!("serialize tx: {e}")))?;
    Ok(tagged)
}

/// A MIP-0006 offer payload as an indexer serves it. Fields this check doesn't use (`expiresAt`,
/// `inputNullifiers`, `status`, …) are ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OfferPayloadJson {
    version: u32,
    #[serde(default)]
    offer_id: Option<String>,
    #[serde(default)]
    offer_bech32: Option<String>,
    computed: ComputedJson,
}

#[derive(Debug, Deserialize)]
struct ComputedJson {
    gives: Vec<TokenLegJson>,
    wants: Vec<TokenLegJson>,
}

#[derive(Debug, Deserialize)]
struct TokenLegJson {
    token: String,
    amount: String,
    #[serde(rename = "type")]
    layer: String,
}

/// The value layer a leg moves on, as MIP-0006 tags it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Shielded,
    Unshielded,
}

/// Net amount per (layer, wire token): what an offer gives, or what it wants.
type Legs = BTreeMap<(Layer, String), u128>;

/// Validate a MIP-0006 offer payload and return its offer as tagged transaction bytes.
///
/// The offer itself is authoritative: gives and wants are derived from the transaction and must match
/// what the payload's `computed` advertises exactly, so a misadvertised offer is refused rather than
/// completed on the wrong terms. An offer that gives without wanting anything is refused too, since
/// MIP-0006 forbids a taker from settling one. `offerBech32` is required: a list response may carry
/// only `offerId`, which has no bytes to complete.
pub(super) fn decode_offer_payload(json: &str) -> Result<Vec<u8>, std::io::Error> {
    let payload: OfferPayloadJson = serde_json::from_str(json)
        .map_err(|e| err(format!("invalid MIP-0006 offer payload: {e}")))?;
    if payload.version != 1 {
        return Err(err(format!(
            "unsupported MIP-0006 offer payload version {}",
            payload.version
        )));
    }
    let offer = payload.offer_bech32.as_deref().ok_or_else(|| {
        err(
            "MIP-0006 offer payload has no offerBech32; fetch the single offer from the indexer, \
             or pass its swapoffer string directly",
        )
    })?;
    let raw = swap_offer_bytes(offer)?;
    if let Some(id) = payload.offer_id.as_deref() {
        let actual = hex::encode(Sha256::digest(&raw));
        if !id.eq_ignore_ascii_case(&actual) {
            return Err(err(format!(
                "MIP-0006 offerId {id} does not match the offer, whose SHA-256 is {actual}"
            )));
        }
    }
    let tagged = retag(raw)?;
    let (gives, wants) = derived_legs(&tagged)?;
    ensure_two_sided(&gives, &wants)?;
    ensure_matches(
        &advertised_legs(&payload.computed.gives, "gives")?,
        &gives,
        "gives",
    )?;
    ensure_matches(
        &advertised_legs(&payload.computed.wants, "wants")?,
        &wants,
        "wants",
    )?;
    Ok(tagged)
}

/// Derive an offer's gives and wants from its ledger balance, netted across segments: a positive
/// balance is a token the maker gives, a negative one a token it wants. DUST is fee capacity, not a
/// leg. The netting hides no split, since `balanceSealed` refuses an offer that moves value outside
/// the guaranteed section.
fn derived_legs(tagged: &[u8]) -> Result<(Legs, Legs), std::io::Error> {
    if !is_sealed_maker_payload(tagged) {
        return Err(err("the MIP-0006 offer is not a sealed transaction"));
    }
    let tx: TxSealed = tagged_deserialize(&mut &tagged[..])
        .map_err(|e| err(format!("failed to parse the offer transaction: {e}")))?;
    let balance = tx
        .balance(None)
        .map_err(|e| err(format!("offer balance check failed: {e:?}")))?;

    let mut net: BTreeMap<(Layer, String), i128> = BTreeMap::new();
    for ((token, _segment), bal) in balance {
        let key = match token {
            LedgerTokenType::Shielded(tt) => (Layer::Shielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Unshielded(tt) => (Layer::Unshielded, hex::encode(tt.0 .0)),
            LedgerTokenType::Dust => continue,
        };
        let slot = net.entry(key).or_default();
        *slot = slot
            .checked_add(bal)
            .ok_or_else(|| err("offer balance overflow"))?;
    }
    let (mut gives, mut wants) = (Legs::new(), Legs::new());
    for (key, bal) in net {
        if bal > 0 {
            gives.insert(key, bal.unsigned_abs());
        } else if bal < 0 {
            wants.insert(key, bal.unsigned_abs());
        }
    }
    Ok((gives, wants))
}

fn ensure_two_sided(gives: &Legs, wants: &Legs) -> Result<(), std::io::Error> {
    if gives.is_empty() || wants.is_empty() {
        return Err(err(
            "a MIP-0006 offer must both give and want a token; refusing a one-sided offer",
        ));
    }
    Ok(())
}

/// Sum an advertised gives/wants list into [`Legs`], tokens normalized to their wire form. A zero
/// amount is refused, and repeated tokens add up.
fn advertised_legs(entries: &[TokenLegJson], label: &str) -> Result<Legs, std::io::Error> {
    let mut out = Legs::new();
    for entry in entries {
        let layer = match entry.layer.as_str() {
            "SHIELDED" => Layer::Shielded,
            "UNSHIELDED" => Layer::Unshielded,
            other => {
                return Err(err(format!(
                    "MIP-0006 {label} entry has an unknown type {other:?}"
                )))
            }
        };
        let token = crate::parse_token_type(Some(&entry.token))?.to_wire_token_type();
        let amount = entry
            .amount
            .trim()
            .parse::<u128>()
            .map_err(|e| err(format!("invalid MIP-0006 amount {:?}: {e}", entry.amount)))?;
        if amount == 0 {
            return Err(err(format!(
                "MIP-0006 {label} entry for token {token} must be non-zero"
            )));
        }
        let slot = out.entry((layer, token)).or_insert(0);
        *slot = slot
            .checked_add(amount)
            .ok_or_else(|| err(format!("MIP-0006 {label} amount overflow")))?;
    }
    Ok(out)
}

fn ensure_matches(advertised: &Legs, actual: &Legs, label: &str) -> Result<(), std::io::Error> {
    if advertised == actual {
        return Ok(());
    }
    Err(err(format!(
        "MIP-0006 {label} do not match the offer (advertised {advertised:?}, offer {actual:?})"
    )))
}

/// Encode transaction bytes as a MIP-0005 `swapoffer1…` string, without the 90-character cap.
#[cfg(test)]
pub(super) fn encode_swap_offer(bytes: &[u8]) -> String {
    use bech32::{ByteIterExt as _, Fe32IterExt as _, Hrp};
    let hrp = Hrp::parse(SWAP_OFFER_HRP).expect("valid HRP");
    bytes
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .chars()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_serialize::{tagged_deserialize, Serializable as _};

    fn sealed_maker() -> Vec<u8> {
        let hex_str = include_str!("testdata/sealed_maker_preprod.hex").trim();
        hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str)).unwrap()
    }

    #[test]
    fn round_trips_a_sealed_maker() {
        let bytes = sealed_maker();
        let offer = encode_swap_offer(&bytes);
        assert!(offer.starts_with("swapoffer1"));
        assert!(
            offer.len() > 90,
            "a real offer exceeds bech32's 90-character cap"
        );
        assert!(is_swap_offer(&offer));
        assert_eq!(decode_swap_offer(&offer).unwrap(), bytes);
    }

    #[test]
    fn accepts_an_all_uppercase_offer() {
        let bytes = sealed_maker();
        let upper = encode_swap_offer(&bytes).to_ascii_uppercase();
        assert!(is_swap_offer(&upper));
        assert_eq!(decode_swap_offer(&upper).unwrap(), bytes);
    }

    #[test]
    fn retags_an_untagged_payload() {
        let tagged = sealed_maker();
        let tx: TxSealed = tagged_deserialize(&mut tagged.as_slice()).unwrap();
        let mut untagged = Vec::new();
        tx.serialize(&mut untagged).unwrap();
        assert!(!untagged.starts_with(b"midnight:"));
        assert_eq!(
            decode_swap_offer(&encode_swap_offer(&untagged)).unwrap(),
            tagged
        );
    }

    #[test]
    fn rejects_a_wrong_hrp_or_a_bad_checksum() {
        use bech32::{ByteIterExt as _, Fe32IterExt as _, Hrp};
        let bytes = sealed_maker();
        let old_hrp: String = bytes
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&Hrp::parse("zswapoffer").unwrap())
            .chars()
            .collect();
        assert!(!is_swap_offer(&old_hrp));
        assert!(decode_swap_offer(&old_hrp).is_err());

        let mut corrupted = encode_swap_offer(&bytes);
        let last = corrupted.pop().unwrap();
        corrupted.push(if last == 'q' { 'p' } else { 'q' });
        assert!(decode_swap_offer(&corrupted).is_err());
    }

    /// A sealed offer that gives 600 000 NIGHT and wants 50 of an unshielded token.
    fn two_sided_offer() -> Vec<u8> {
        use midnight_base_crypto::hash::HashOutput;
        use midnight_base_crypto::signatures::SigningKey;
        use midnight_base_crypto::time::Timestamp;
        use midnight_coin_structure::coin::{UnshieldedTokenType, UserAddress, NIGHT};
        use midnight_ledger::structure::{
            Intent, IntentHash, StandardTransaction, UnshieldedOffer, UtxoOutput, UtxoSpend,
        };
        use midnight_storage::arena::Sp;
        use midnight_storage::storage::HashMap as MnHashMap;
        use rand::rngs::StdRng;
        use rand::SeedableRng as _;
        use transient_crypto::commitment::PedersenRandomness;

        let vk = SigningKey::from_bytes(&[0x11; 32]).unwrap().verifying_key();
        let owner = UserAddress::from(vk.clone());
        let offer = UnshieldedOffer {
            inputs: vec![UtxoSpend {
                value: 1_000_000,
                owner: vk,
                type_: NIGHT,
                intent_hash: IntentHash(HashOutput([7; 32])),
                output_no: 0,
            }]
            .into(),
            outputs: vec![
                UtxoOutput {
                    value: 400_000,
                    owner,
                    type_: NIGHT,
                },
                UtxoOutput {
                    value: 50,
                    owner,
                    type_: UnshieldedTokenType(HashOutput([0x22; 32])),
                },
            ]
            .into(),
            signatures: vec![].into(),
        };
        let intent: Intent<MnSig, ProofMarker, PedersenRandomness, InMemoryDB> = Intent {
            guaranteed_unshielded_offer: Some(Sp::new(offer)),
            fallible_unshielded_offer: None,
            actions: vec![].into(),
            dust_actions: None,
            ttl: Timestamp::from_secs(0),
            binding_commitment: Default::default(),
        };
        let tx = Transaction::Standard(StandardTransaction {
            network_id: "midnight:test".to_string(),
            intents: MnHashMap::new().insert(1, intent),
            guaranteed_coins: None,
            fallible_coins: MnHashMap::new(),
            binding_randomness: Default::default(),
        })
        .seal(StdRng::seed_from_u64(0));
        let mut out = Vec::new();
        tagged_serialize(&tx, &mut out).unwrap();
        out
    }

    fn payload(bytes: &[u8], gives: &str, wants: &str) -> String {
        format!(
            r#"{{"version":1,"offerId":"{}","offerBech32":"{}","computed":{{"gives":{gives},"wants":{wants},"inputNullifiers":[],"firstSeenAt":"2026-10-26T00:00:00Z","status":"live"}}}}"#,
            hex::encode(Sha256::digest(bytes)),
            encode_swap_offer(bytes),
        )
    }

    const NIGHT_WIRE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn gives_night(amount: &str) -> String {
        format!(r#"[{{"token":"{NIGHT_WIRE}","amount":"{amount}","type":"UNSHIELDED"}}]"#)
    }

    fn wants_token(layer: &str) -> String {
        format!(
            r#"[{{"token":"0x{}","amount":"50","type":"{layer}"}}]"#,
            "22".repeat(32)
        )
    }

    #[test]
    fn completes_a_payload_whose_terms_match_the_offer() {
        let bytes = two_sided_offer();
        let json = payload(&bytes, &gives_night("600000"), &wants_token("UNSHIELDED"));
        assert_eq!(decode_offer_payload(&json).unwrap(), bytes);
    }

    #[test]
    fn refuses_misadvertised_terms() {
        let bytes = two_sided_offer();
        for json in [
            payload(&bytes, &gives_night("600001"), &wants_token("UNSHIELDED")),
            payload(&bytes, &gives_night("600000"), &wants_token("SHIELDED")),
            payload(&bytes, &gives_night("600000"), "[]"),
            payload(&bytes, &gives_night("0"), &wants_token("UNSHIELDED")),
            payload(&bytes, &gives_night("600000"), &wants_token("NIGHT")),
        ] {
            assert!(decode_offer_payload(&json).is_err(), "{json}");
        }
    }

    #[test]
    fn refuses_a_give_only_offer() {
        // The preprod fixture gives 500 000 NIGHT and wants nothing.
        let bytes = sealed_maker();
        let (gives, wants) = derived_legs(&bytes).unwrap();
        assert_eq!(
            gives,
            Legs::from([((Layer::Unshielded, NIGHT_WIRE.to_string()), 500_000)])
        );
        assert!(wants.is_empty());
        let json = payload(&bytes, &gives_night("500000"), "[]");
        let e = decode_offer_payload(&json).unwrap_err();
        assert!(e.to_string().contains("one-sided"), "{e}");
    }

    #[test]
    fn refuses_a_payload_without_the_offer_or_with_a_wrong_offer_id() {
        let bytes = two_sided_offer();
        let good = payload(&bytes, &gives_night("600000"), &wants_token("UNSHIELDED"));
        let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();

        v["offerId"] = serde_json::Value::String("00".repeat(32));
        assert!(decode_offer_payload(&v.to_string())
            .unwrap_err()
            .to_string()
            .contains("offerId"));

        v.as_object_mut().unwrap().remove("offerBech32");
        assert!(decode_offer_payload(&v.to_string())
            .unwrap_err()
            .to_string()
            .contains("offerBech32"));

        let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
        v["version"] = 2.into();
        assert!(decode_offer_payload(&v.to_string()).is_err());
    }
}
