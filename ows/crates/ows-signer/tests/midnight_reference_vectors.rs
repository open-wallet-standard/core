//! Midnight keys, addresses and message signatures checked against vectors that other
//! implementations produced, not OWS. The fixtures name their source, commit and license:
//!
//! - `fixtures/midnight-wallet-spec.json`: the Midnight wallet specification's reference vectors
//!   (midnightntwrk/midnight-wallet, `packages/spec-reference/test-vectors`).
//! - `fixtures/mip-0031-vectors.json`: MIP-0031's message-signing vectors
//!   (midnightntwrk/midnight-improvement-proposals, `mips/mip-0031-message-signing`).

use k256::schnorr::signature::Verifier as _;
use ows_signer::chains::midnight::signed_message_bytes;
use ows_signer::chains::MidnightSigner;
use ows_signer::{ChainSigner, DerivedKey, HdDeriver, Mnemonic, SecretBytes};
use serde_json::Value;
use sha2::Digest as _;

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn bytes(hex_str: &Value) -> Vec<u8> {
    hex::decode(hex_str.as_str().unwrap()).unwrap()
}

fn signer_for(network_id: &Value) -> MidnightSigner {
    match network_id.as_str() {
        None => MidnightSigner::mainnet(),
        Some(id) => MidnightSigner::from_chain_id(&format!("midnight:{id}")),
    }
}

/// The packed signing key OWS builds for an account whose unshielded, shielded and dust roles
/// derive `seeds`, in that order.
fn signing_key(seeds: [&[u8]; 3]) -> SecretBytes {
    let signer = MidnightSigner::mainnet();
    let keys: Vec<DerivedKey> = signer
        .default_derivation_paths(0)
        .into_iter()
        .zip(seeds)
        .map(|(path, seed)| DerivedKey {
            path,
            secret: SecretBytes::from_slice(seed),
        })
        .collect();
    signer.encode_keys(&keys).unwrap()
}

#[test]
fn role_seeds_match_the_wallet_spec_at_each_account() {
    let vectors = fixture("midnight-wallet-spec.json");
    let vectors = vectors["seedDerivation"].as_array().unwrap();
    assert!(!vectors.is_empty());
    let signer = MidnightSigner::mainnet();
    for v in vectors {
        let master = bytes(&v["masterSeed"]);
        let account = u32::try_from(v["account"].as_u64().unwrap()).unwrap();
        let roles = &v["seedsByRole"];
        let paths = signer.default_derivation_paths(account);
        for (path, role) in paths.iter().zip(["UnshieldedExternal", "Shielded", "Dust"]) {
            assert_eq!(
                path,
                roles[role]["path"].as_str().unwrap(),
                "{role} at {account}"
            );
            let seed = HdDeriver::derive(&master, path, signer.curve()).unwrap();
            assert_eq!(
                seed.expose(),
                bytes(&roles[role]["seed"]).as_slice(),
                "{role} seed of {} at {path}",
                v["masterSeed"]
            );
        }
    }
}

#[test]
fn message_signing_keys_match_the_wallet_spec_unshielded_keys() {
    let vectors = fixture("midnight-wallet-spec.json");
    let vectors = vectors["keyDerivation"].as_array().unwrap();
    assert!(!vectors.is_empty());
    let signer = MidnightSigner::mainnet();
    for v in vectors {
        let seed = bytes(&v["seed"]);
        let key = signing_key([&seed, &seed, &seed]);
        let signed = signer.sign_message(key.expose(), b"", None);
        match v["unshielded"]["publicKey"].as_str() {
            Some(public_key) => assert_eq!(
                hex::encode(signed.unwrap().public_key.unwrap()),
                public_key,
                "seed {}",
                v["seed"]
            ),
            // Not a valid secp256k1 scalar, so the spec derives no unshielded key from it.
            None => assert!(signed.is_err(), "seed {}", v["seed"]),
        }
    }
}

#[test]
fn addresses_match_the_wallet_spec_on_every_network() {
    let vectors = fixture("midnight-wallet-spec.json");
    let vectors = vectors["addresses"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let seed = bytes(&v["seed"]);
        let key = signing_key([&seed, &seed, &seed]);
        let derived = signer_for(&v["networkId"]).derive_addresses(key.expose());
        let label = format!("seed {} on {}", v["seed"], v["networkId"]);
        let Some(unshielded) = v["unshieldedAddress"]["bech32m"].as_str() else {
            assert!(derived.is_err(), "{label}");
            continue;
        };
        let derived = derived.unwrap();
        assert_eq!(derived.unshielded, unshielded, "{label}");
        assert_eq!(
            derived.shielded,
            v["shieldedAddress"]["bech32m"].as_str().unwrap(),
            "{label}"
        );
        assert_eq!(
            derived.dust,
            v["dustAddress"]["bech32m"].as_str().unwrap(),
            "{label}"
        );
    }
}

/// The 24-word phrase of input-output-hk/lace#2133, whose unshielded preview address differs between
/// the Midnight SDK (`@midnight-ntwrk/wallet-sdk-hd` from the 64-byte BIP-39 seed, address bytes
/// `2d8c83c0…`) and Lace (the seed's first 32 bytes, `a4bf6c8b…`). OWS seeds from the 64-byte seed,
/// so it must give the SDK's address.
#[test]
fn a_mnemonic_derives_the_midnight_sdk_address_not_the_truncated_seed_one() {
    const SDK: &str = "mn_addr_preview19kxg8sxrsty37elmm6yd68tuy7prryjst2r48eapf2fdtd8z4gpq8xczf2";
    const TRUNCATED_SEED: &str =
        "mn_addr_preview15jlkezafp4mju3v7cdh3ywre2y2s3szgpqrkw8p4tzxjqhuaqhlshsa9pv";
    let phrase = format!("{}art", "abandon ".repeat(23));
    let mnemonic = Mnemonic::from_phrase(&phrase).unwrap();
    let signer = MidnightSigner::preview();
    let keys = HdDeriver::derive_keys_from_mnemonic(
        &mnemonic,
        "",
        signer.default_derivation_paths(0),
        signer.curve(),
    )
    .unwrap();
    let key = signer.encode_keys(&keys).unwrap();
    let unshielded = signer.derive_addresses(key.expose()).unwrap().unshielded;
    assert_eq!(unshielded, SDK);
    assert_ne!(unshielded, TRUNCATED_SEED);
}

#[test]
fn message_signatures_match_the_mip_0031_vectors() {
    let file = fixture("mip-0031-vectors.json");
    assert_eq!(file["schemaVersion"], 1);
    let valid: Vec<&Value> = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["valid"] == true)
        .collect();
    assert!(!valid.is_empty());
    let signer = MidnightSigner::mainnet();
    for v in valid {
        let name = v["name"].as_str().unwrap();
        assert_eq!(v["scheme"], "schnorr_bip340", "{name}");
        let key = &file["keys"][v["key"].as_str().unwrap()];
        let secret = bytes(&key["schnorrSigningKeyHex"]);
        let payload = bytes(&v["payloadHex"]);
        assert_eq!(payload.len() as u64, v["payloadLength"].as_u64().unwrap());

        let message = signed_message_bytes(&payload);
        assert_eq!(
            hex::encode(&message),
            v["messageHex"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(v["signature"]["data"], v["messageHex"], "{name}");
        let digest: [u8; 32] = sha2::Sha256::digest(&message).into();
        assert_eq!(
            hex::encode(digest),
            v["messageDigestHex"].as_str().unwrap(),
            "{name}"
        );

        let ows = signer
            .sign_message(
                signing_key([&secret, &[0x22; 32], &[0x33; 32]]).expose(),
                &payload,
                None,
            )
            .unwrap();
        let public_key = ows.public_key.unwrap();
        assert_eq!(
            hex::encode(&public_key),
            key["schnorrVerifyingKey"].as_str().unwrap()
        );
        assert_eq!(
            v["signature"]["verifyingKey"], key["schnorrVerifyingKey"],
            "{name}"
        );
        let vk = k256::schnorr::VerifyingKey::from_bytes(&public_key).unwrap();
        let ows_signature = k256::schnorr::Signature::try_from(ows.signature.as_slice()).unwrap();
        vk.verify(&message, &ows_signature)
            .unwrap_or_else(|_| panic!("{name}: the OWS signature does not verify"));

        // The vector signs with fixed auxiliary randomness and OWS with none, so the two signatures
        // differ; given the vector's, the same BIP-340 signer reproduces it byte for byte.
        let expected = bytes(&v["signature"]["signature"]);
        let reference = k256::schnorr::Signature::try_from(expected.as_slice()).unwrap();
        vk.verify(&message, &reference)
            .unwrap_or_else(|_| panic!("{name}: the vector's signature does not verify"));
        let aux: [u8; 32] = bytes(&v["auxRandHex"]).try_into().unwrap();
        let reproduced = k256::schnorr::SigningKey::from_bytes(&secret)
            .unwrap()
            .sign_prehash_with_aux_rand(&digest, &aux)
            .unwrap();
        assert_eq!(
            reproduced.to_bytes().as_slice(),
            expected.as_slice(),
            "{name}"
        );
    }
}

/// Each rejected vector carries a genuine signature over some other message: one built on a foreign
/// prefix, a padded, unterminated or wrong length, or another payload. None of them may be a
/// signature over the frame OWS builds for the payload.
#[test]
fn no_mip_0031_rejection_is_a_signature_over_the_ows_frame() {
    let file = fixture("mip-0031-vectors.json");
    let rejected: Vec<&Value> = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["valid"] == false)
        .collect();
    assert!(!rejected.is_empty());
    for v in rejected {
        let name = v["name"].as_str().unwrap();
        assert_eq!(v["kind"], "verification", "{name}");
        let message = signed_message_bytes(&bytes(&v["payloadHex"]));
        let signature = &v["signature"];
        let vk =
            k256::schnorr::VerifyingKey::from_bytes(&bytes(&signature["verifyingKey"])).unwrap();
        let sig =
            k256::schnorr::Signature::try_from(bytes(&signature["signature"]).as_slice()).unwrap();
        assert!(vk.verify(&message, &sig).is_err(), "{name}");
    }
}
