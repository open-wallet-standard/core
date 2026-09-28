//! The DUST registrations a transaction someone else authored carries, read off the ledger structure for
//! the policy seam.
//!
//! A registration points a NIGHT key's DUST generation at a dust address or, with no address, stops it.
//! The signer signs every registration keyed by the wallet's own NIGHT key, so one a DApp puts in a
//! transaction it hands the wallet redirects or ends the wallet's DUST generation once signed. Neither
//! the effects nor the contracts show that; this list does, so a policy can allow or deny it.

use std::ops::Deref as _;

use midnight_base_crypto::signatures::VerifyingKey;
use midnight_ledger::dust::{DustPublicKey, DustRegistration};
use midnight_ledger::structure::{ProofKind, SignatureKind, StandardTransaction};
use midnight_serialize::Serializable as _;
use midnight_storage::db::DB;
use midnight_storage::Storable;
use ows_signer::chains::{MidnightCryptoProvider, MidnightSigner};

/// One DUST registration in the transaction, and how it relates to the wallet.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RequestedDustRegistration {
    /// The id of the intent carrying the registration.
    pub intent: u16,
    /// The NIGHT verifying key whose DUST generation the registration directs, hex-encoded the way the
    /// indexer reports a UTXO's owner.
    pub night_key: String,
    /// The dust address the generation is directed to, or `None` (JSON `null`) for a deregistration.
    pub dust_address: Option<String>,
    /// The most of the registered generation's DUST the transaction may spend on its fee, as a decimal
    /// string.
    pub allow_fee_payment: String,
    /// Whether `night_key` is this wallet's own NIGHT key — the registrations the wallet signs.
    pub wallet_key: bool,
    /// Whether `dust_address` is this wallet's own dust address.
    pub to_wallet: bool,
}

/// The wallet's own NIGHT and dust keys, which each registration is judged against, and the signer for
/// the transaction's network, which encodes a registration's target as an address.
pub(crate) struct WalletDustKeys {
    night_key: VerifyingKey,
    dust_key: DustPublicKey,
    signer: MidnightSigner,
}

impl WalletDustKeys {
    pub(crate) fn new(
        chain_id: &str,
        crypto_provider: &MidnightCryptoProvider,
    ) -> Result<Self, std::io::Error> {
        let to_io = |e: ows_signer::SignerError| std::io::Error::other(e.to_string());
        Ok(Self {
            night_key: crypto_provider.unshielded_verifying_key().map_err(to_io)?,
            dust_key: crypto_provider.dust_public_key().map_err(to_io)?,
            signer: MidnightSigner::from_chain_id(chain_id),
        })
    }
}

/// Every registration a transaction's intents carry, each with the id of the intent carrying it.
pub(crate) fn intent_registrations<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB>(
    tx: &StandardTransaction<S, P, B, D>,
) -> Vec<(u16, DustRegistration<S, D>)> {
    let mut out = Vec::new();
    for pair in tx.intents.iter() {
        let (id, intent) = pair.deref();
        if let Some(actions) = intent.deref().dust_actions.as_ref() {
            for reg in actions.deref().registrations.iter() {
                out.push((*id.deref(), reg.deref().clone()));
            }
        }
    }
    out
}

/// The registrations carried by a transaction's intents, each as `(intent id, registration)`. Pure over
/// the ledger structure, so it is the unit-tested core behind every plan's `dust_registrations()`.
pub(crate) fn requested_dust_registrations<S: SignatureKind<D>, D: DB>(
    registrations: impl IntoIterator<Item = (u16, DustRegistration<S, D>)>,
    wallet: &WalletDustKeys,
) -> Result<Vec<RequestedDustRegistration>, std::io::Error> {
    let own_night_key = night_key_hex(&wallet.night_key)?;
    registrations
        .into_iter()
        .map(|(intent, reg)| {
            let night_key = night_key_hex(&reg.night_key)?;
            let target = reg.dust_address.as_ref().map(|pk| *pk.deref());
            let dust_address = target
                .as_ref()
                .map(|pk| wallet.signer.dust_address(pk))
                .transpose()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            Ok(RequestedDustRegistration {
                intent,
                wallet_key: night_key == own_night_key,
                to_wallet: target.as_ref() == Some(&wallet.dust_key),
                night_key,
                dust_address,
                allow_fee_payment: reg.allow_fee_payment.to_string(),
            })
        })
        .collect()
}

fn night_key_hex(key: &VerifyingKey) -> Result<String, std::io::Error> {
    let mut raw = Vec::new();
    key.serialize(&mut raw)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(hex::encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::signatures::SigningKey;
    use midnight_ledger::dust::DustSecretKey;
    use midnight_storage::arena::Sp;
    use midnight_storage::db::InMemoryDB;

    type Registration = DustRegistration<(), InMemoryDB>;

    fn night_key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).unwrap().verifying_key()
    }

    fn dust_key(seed: u8) -> DustPublicKey {
        DustPublicKey::from(DustSecretKey::derive_secret_key(&[seed; 32]))
    }

    fn wallet() -> WalletDustKeys {
        WalletDustKeys {
            night_key: night_key(1),
            dust_key: dust_key(2),
            signer: MidnightSigner::preprod(),
        }
    }

    fn registration(night: u8, dust: Option<u8>, allow_fee_payment: u128) -> Registration {
        DustRegistration {
            night_key: night_key(night),
            dust_address: dust.map(|seed| Sp::new(dust_key(seed))),
            allow_fee_payment,
            signature: None,
        }
    }

    #[test]
    fn a_self_registration_is_the_wallets_key_to_the_wallet() {
        let out =
            requested_dust_registrations([(3, registration(1, Some(2), 0))], &wallet()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].intent, 3);
        assert!(out[0].wallet_key && out[0].to_wallet);
        assert_eq!(
            out[0].dust_address.as_deref(),
            Some(
                MidnightSigner::preprod()
                    .dust_address(&dust_key(2))
                    .unwrap()
                    .as_str()
            )
        );
        assert!(out[0]
            .dust_address
            .as_ref()
            .unwrap()
            .starts_with("mn_dust_preprod1"));
        assert_eq!(out[0].night_key, night_key_hex(&night_key(1)).unwrap());
    }

    #[test]
    fn a_redirect_of_the_wallets_generation_is_flagged() {
        let out = requested_dust_registrations([(5, registration(1, Some(9), 100_000))], &wallet())
            .unwrap();
        assert!(out[0].wallet_key);
        assert!(!out[0].to_wallet);
        assert_eq!(out[0].allow_fee_payment, "100000");
    }

    #[test]
    fn a_deregistration_has_no_target() {
        let out = requested_dust_registrations([(5, registration(1, None, 0))], &wallet()).unwrap();
        assert!(out[0].wallet_key);
        assert_eq!(out[0].dust_address, None);
        assert!(!out[0].to_wallet);
    }

    #[test]
    fn another_keys_registration_is_not_the_wallets() {
        let out =
            requested_dust_registrations([(5, registration(7, Some(2), 0))], &wallet()).unwrap();
        assert!(!out[0].wallet_key);
        assert!(out[0].to_wallet);
    }

    #[test]
    fn a_deregistration_serializes_its_target_as_null() {
        let out = requested_dust_registrations([(5, registration(1, None, 0))], &wallet()).unwrap();
        let json = serde_json::to_value(&out[0]).unwrap();
        assert!(json["dust_address"].is_null());
        assert_eq!(json["allow_fee_payment"], "0");
    }
}
