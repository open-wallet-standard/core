use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use k256::ecdsa::SigningKey;
use ows_core::ChainType;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

#[cfg(feature = "zcash-shielded")]
use zcash_keys::keys::{ReceiverRequirement, UnifiedSpendingKey};
#[cfg(feature = "zcash-shielded")]
use zcash_protocol::consensus::Network;

/// Zcash transparent chain signer.
///
/// Handles t-address derivation and transparent transaction signing.
/// Zcash transparent uses the same secp256k1 curve as Bitcoin with
/// a different address encoding (Base58Check with Zcash-specific
/// two-byte version prefix, per § 5.6.1 of the protocol spec).
///
/// # Transaction signing
///
/// Zcash sighash computation uses BLAKE2b-256 with a consensus-branch-specific
/// personalization string (ZIP-244). Because this requires knowledge of the
/// consensus branch ID, `sign_transaction` expects a pre-computed 32-byte
/// sighash — not raw transaction bytes. The caller (e.g. a PCZT builder or
/// lightwalletd client) is responsible for computing the sighash per ZIP-244.
///
/// # Message signing
///
/// Follows the same format as zcashd's `signmessage` RPC: a double-SHA256
/// of the magic-prefixed message, using "Zcash Signed Message:\n" as the
/// magic string (cf. `strMessageMagic` in zcash/src/main.cpp).
///
/// # Shielded transactions
///
/// Shielded (Sapling/Orchard) transactions require zero-knowledge proof
/// generation and use the PCZT format — see the companion RFC.
pub struct ZcashSigner {
    /// Two-byte Base58Check version prefix.
    /// Mainnet P2PKH: [0x1C, 0xB8] → t1...
    /// Testnet P2PKH: [0x1D, 0x25] → tm...
    /// (cf. chainparams.cpp base58Prefixes[PUBKEY_ADDRESS])
    addr_version: [u8; 2],
}

impl ZcashSigner {
    pub fn new(addr_version: [u8; 2]) -> Self {
        ZcashSigner { addr_version }
    }

    pub fn mainnet() -> Self {
        Self::new([0x1C, 0xB8])
    }

    pub fn testnet() -> Self {
        Self::new([0x1D, 0x25])
    }

    /// Select mainnet or testnet based on CAIP-2 chain identifier.
    pub fn from_chain_id(chain_id: &str) -> Self {
        if chain_id.contains("testnet") {
            Self::testnet()
        } else {
            Self::mainnet()
        }
    }

    #[cfg(feature = "zcash-shielded")]
    fn network(&self) -> Network {
        if self.addr_version == [0x1C, 0xB8] {
            Network::MainNetwork
        } else {
            Network::TestNetwork
        }
    }

    /// Derive a unified address (t + sapling + orchard receivers) from a
    /// raw BIP-39 seed using ZIP-32 derivation.
    #[cfg(feature = "zcash-shielded")]
    pub fn derive_unified_address(
        &self,
        seed: &[u8],
        account_index: u32,
    ) -> Result<String, SignerError> {
        if seed.len() < 32 {
            return Err(SignerError::AddressDerivationFailed(format!(
                "seed must be at least 32 bytes, got {}",
                seed.len()
            )));
        }

        let network = self.network();
        let account = zip32::AccountId::try_from(account_index).map_err(|e| {
            SignerError::AddressDerivationFailed(format!("invalid account index: {e}"))
        })?;

        let usk = UnifiedSpendingKey::from_seed(&network, seed, account).map_err(|e| {
            SignerError::AddressDerivationFailed(format!("ZIP-32 key derivation failed: {e:?}"))
        })?;

        let ufvk = usk.to_unified_full_viewing_key();

        let request = zcash_keys::keys::UnifiedAddressRequest::unsafe_custom(
            ReceiverRequirement::Require,
            ReceiverRequirement::Require,
            ReceiverRequirement::Omit,
        );

        let (ua, _diversifier_index) = ufvk.default_address(request).map_err(|e| {
            SignerError::AddressDerivationFailed(format!(
                "unified address derivation failed: {e}"
            ))
        })?;

        Ok(ua.encode(&network))
    }

    /// Sign a PCZT (Partially Created Zcash Transaction).
    ///
    /// OWS acts as the Signer role: it receives a PCZT that has already been
    /// through Creator + Prover, applies spend authorization signatures for
    /// all transparent, Sapling, and Orchard inputs, and returns the signed PCZT.
    ///
    /// The `seed` must be the raw BIP-39 seed (64 bytes). The USK is derived
    /// via ZIP-32 to extract the per-pool signing keys.
    #[cfg(feature = "zcash-shielded")]
    pub fn sign_pczt(
        &self,
        seed: &[u8],
        pczt_bytes: &[u8],
        account_index: u32,
    ) -> Result<Vec<u8>, SignerError> {
        use zcash_transparent::keys::NonHardenedChildIndex;

        if seed.len() < 32 {
            return Err(SignerError::InvalidPrivateKey(format!(
                "seed must be at least 32 bytes, got {}",
                seed.len()
            )));
        }

        let network = self.network();
        let account = zip32::AccountId::try_from(account_index).map_err(|e| {
            SignerError::SigningFailed(format!("invalid account index: {e}"))
        })?;

        let usk = UnifiedSpendingKey::from_seed(&network, seed, account).map_err(|e| {
            SignerError::SigningFailed(format!("ZIP-32 key derivation failed: {e:?}"))
        })?;

        let pczt = pczt::Pczt::parse(pczt_bytes).map_err(|e| {
            SignerError::InvalidTransaction(format!("failed to parse PCZT: {e:?}"))
        })?;

        let n_transparent = pczt.transparent().inputs().len();
        let n_sapling = pczt.sapling().spends().len();
        let n_orchard = pczt.orchard().actions().len();

        let mut signer = pczt::roles::signer::Signer::new(pczt).map_err(|e| {
            SignerError::SigningFailed(format!("failed to initialize PCZT signer: {e:?}"))
        })?;

        if n_transparent > 0 {
            // Derive external scope at index 0 (the primary receiving address).
            // Inputs at other indices are skipped via TransparentSign error below,
            // consistent with how Sapling/Orchard skip non-matching keys.
            let scope = zcash_transparent::keys::TransparentKeyScope::from(
                zip32::Scope::External,
            );
            let transparent_sk = usk
                .transparent()
                .derive_secret_key(scope, NonHardenedChildIndex::ZERO)
                .map_err(|e| {
                    SignerError::SigningFailed(format!(
                        "failed to derive transparent secret key: {e:?}"
                    ))
                })?;
            for i in 0..n_transparent {
                match signer.sign_transparent(i, &transparent_sk) {
                    Ok(()) => {}
                    Err(pczt::roles::signer::Error::TransparentSign(_)) => {
                        // Not our input (different key) — skip it
                    }
                    Err(e) => {
                        return Err(SignerError::SigningFailed(format!(
                            "transparent input {i} signing failed: {e:?}"
                        )));
                    }
                }
            }
        }

        if n_sapling > 0 {
            let sapling_ask = &usk.sapling().expsk.ask;
            for i in 0..n_sapling {
                match signer.sign_sapling(i, sapling_ask) {
                    Ok(()) => {}
                    Err(pczt::roles::signer::Error::SaplingSign(_)) => {
                        // Not our spend (different key or dummy) — skip it
                    }
                    Err(e) => {
                        return Err(SignerError::SigningFailed(format!(
                            "sapling spend {i} signing failed: {e:?}"
                        )));
                    }
                }
            }
        }

        if n_orchard > 0 {
            let orchard_ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
            for i in 0..n_orchard {
                match signer.sign_orchard(i, &orchard_ask) {
                    Ok(()) => {}
                    Err(pczt::roles::signer::Error::OrchardSign(
                        orchard::pczt::SignerError::WrongSpendAuthorizingKey,
                    )) => {
                        // Not our action (dummy/padding spend) — skip it
                    }
                    Err(e) => {
                        return Err(SignerError::SigningFailed(format!(
                            "orchard action {i} signing failed: {e:?}"
                        )));
                    }
                }
            }
        }

        let signed_pczt = signer.finish();
        Ok(signed_pczt.serialize())
    }

    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        SigningKey::from_slice(private_key)
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))
    }

    fn hash160(data: &[u8]) -> Vec<u8> {
        let sha256 = Sha256::digest(data);
        let ripemd = Ripemd160::digest(sha256);
        ripemd.to_vec()
    }
}

/// Encode an integer as a Bitcoin/Zcash CompactSize (varint).
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

impl ChainSigner for ZcashSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Zcash
    }

    fn curve(&self) -> Curve {
        Curve::Secp256k1
    }

    fn coin_type(&self) -> u32 {
        133
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();

        let pubkey_compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = pubkey_compressed.as_bytes();

        let hash = Self::hash160(pubkey_bytes);

        // Base58Check: version_bytes (2) ++ hash160 (20) ++ checksum (4)
        let mut payload = Vec::with_capacity(2 + 20 + 4);
        payload.extend_from_slice(&self.addr_version);
        payload.extend_from_slice(&hash);

        let checksum = Sha256::digest(Sha256::digest(&payload));
        payload.extend_from_slice(&checksum[..4]);

        Ok(bs58::encode(&payload).into_string())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        if message.len() != 32 {
            return Err(SignerError::InvalidMessage(format!(
                "expected 32-byte hash, got {} bytes",
                message.len()
            )));
        }

        let signing_key = Self::signing_key(private_key)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message)
            .map_err(|e| SignerError::SigningFailed(e.to_string()))?;

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        Ok(SignOutput {
            signature: sig_bytes,
            recovery_id: Some(recovery_id.to_byte()),
            public_key: None,
        })
    }

    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        // Zcash transaction sighash is computed per ZIP-244 using BLAKE2b-256
        // with a consensus-branch-specific personalization ("ZcashTxHash_" ||
        // CONSENSUS_BRANCH_ID). Because the signer does not know the branch ID,
        // callers must pre-compute the 32-byte sighash and pass it directly.
        //
        // This matches how PCZT (Partially Created Zcash Transaction) works:
        // the Creator/Prover computes the sighash, and the Signer just signs it.
        if tx_bytes.len() != 32 {
            return Err(SignerError::InvalidTransaction(
                "Zcash requires a pre-computed 32-byte sighash per ZIP-244. \
                 Raw transaction bytes are not supported — use a transaction \
                 builder to compute the sighash (BLAKE2b-256 with branch-specific \
                 personalization) before calling sign_transaction."
                    .to_string(),
            ));
        }
        self.sign(private_key, tx_bytes)
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        // Zcash message signing follows the same format as zcashd signmessage RPC:
        // double-SHA256 of (magic_prefix || CompactSize(message_len) || message).
        //
        // Magic: "\x16Zcash Signed Message:\n"
        //   \x16 = 22 = byte length of "Zcash Signed Message:\n"
        //   (cf. strMessageMagic in zcash/src/main.cpp)
        let prefix = b"\x16Zcash Signed Message:\n";
        let mut data = Vec::new();
        data.extend_from_slice(prefix);
        encode_compact_size(&mut data, message.len());
        data.extend_from_slice(message);

        let hash = Sha256::digest(Sha256::digest(&data));
        self.sign(private_key, &hash)
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/133'/0'/0/{}", index)
    }

    #[cfg(feature = "zcash-shielded")]
    fn needs_raw_seed(&self) -> bool {
        true
    }

    #[cfg(feature = "zcash-shielded")]
    fn derive_address_from_seed(
        &self,
        seed: &[u8],
        account_index: u32,
    ) -> Result<String, SignerError> {
        self.derive_unified_address(seed, account_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_privkey() -> Vec<u8> {
        // Private key = 1 (generator point G)
        let mut privkey = vec![0u8; 31];
        privkey.push(1u8);
        privkey
    }

    #[test]
    fn test_mainnet_t_address_known_value() {
        // Private key = 1 → secp256k1 generator point G
        // Compressed pubkey: 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        // hash160: 751e76e8199196d454941c45d1b3a323f1433bd6
        // Base58Check with version [0x1C, 0xB8] → t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs
        // (independently verified via Python and cross-referenced with Bitcoin's
        // 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH which shares the same hash160)
        let signer = ZcashSigner::mainnet();
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(
            address, "t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs",
            "address must match known value for generator point"
        );
    }

    #[test]
    fn test_testnet_tm_address() {
        let signer = ZcashSigner::testnet();
        let address = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            address.starts_with("tm"),
            "testnet address should start with tm, got: {}",
            address
        );
        assert_eq!(address.len(), 35, "t-addr must be 35 characters");
    }

    #[test]
    fn test_chain_properties() {
        let signer = ZcashSigner::mainnet();
        assert_eq!(signer.chain_type(), ChainType::Zcash);
        assert_eq!(signer.curve(), Curve::Secp256k1);
        assert_eq!(signer.coin_type(), 133);
    }

    #[test]
    fn test_derivation_path() {
        let signer = ZcashSigner::mainnet();
        assert_eq!(signer.default_derivation_path(0), "m/44'/133'/0'/0/0");
        assert_eq!(signer.default_derivation_path(3), "m/44'/133'/0'/0/3");
    }

    #[test]
    fn test_sign_transaction_accepts_32_byte_sighash() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signer = ZcashSigner::mainnet();
        let privkey = test_privkey();

        // Simulate a pre-computed 32-byte sighash (as ZIP-244 would produce)
        let sighash = Sha256::digest(b"simulated ZIP-244 sighash preimage");

        let result = signer.sign_transaction(&privkey, &sighash).unwrap();

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&sighash, &sig)
            .expect("signature must verify against the provided sighash");
    }

    #[test]
    fn test_sign_transaction_rejects_raw_bytes() {
        let signer = ZcashSigner::mainnet();
        let privkey = test_privkey();

        let result = signer.sign_transaction(&privkey, b"not a 32-byte sighash");
        assert!(result.is_err(), "must reject non-32-byte input");

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ZIP-244"),
            "error should reference ZIP-244, got: {}",
            err
        );
    }

    #[test]
    fn test_sign_message_short() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signer = ZcashSigner::mainnet();
        let privkey = test_privkey();
        let message = b"Hello Zcash!";

        let result = signer.sign_message(&privkey, message).unwrap();

        // Verify against correctly constructed hash:
        // \x16 (22) + "Zcash Signed Message:\n" + CompactSize(12) + message
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x16Zcash Signed Message:\n");
        expected_data.push(message.len() as u8);
        expected_data.extend_from_slice(message);
        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature must verify for short messages");
    }

    #[test]
    fn test_sign_message_long_varint() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signer = ZcashSigner::mainnet();
        let privkey = test_privkey();
        let message = vec![0x42u8; 300];

        let result = signer.sign_message(&privkey, &message).unwrap();

        // CompactSize for 300: 0xFD followed by 300 as 2-byte LE
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x16Zcash Signed Message:\n");
        expected_data.push(0xFD);
        expected_data.extend_from_slice(&300u16.to_le_bytes());
        expected_data.extend_from_slice(&message);
        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature must verify for long messages with varint");
    }

    #[test]
    fn test_sign_message_varint_boundary() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;

        let signer = ZcashSigner::mainnet();
        let privkey = test_privkey();
        let message = vec![0xAA; 253];

        let result = signer.sign_message(&privkey, &message).unwrap();

        // 253 is the boundary where single-byte CompactSize becomes invalid
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(b"\x16Zcash Signed Message:\n");
        expected_data.push(0xFD);
        expected_data.extend_from_slice(&253u16.to_le_bytes());
        expected_data.extend_from_slice(&message);
        let expected_hash = Sha256::digest(Sha256::digest(&expected_data));

        let signing_key = SigningKey::from_slice(&privkey).unwrap();
        let verifying_key = signing_key.verifying_key();
        let r: [u8; 32] = result.signature[..32].try_into().unwrap();
        let s: [u8; 32] = result.signature[32..64].try_into().unwrap();
        let sig = k256::ecdsa::Signature::from_scalars(r, s).unwrap();

        verifying_key
            .verify_prehash(&expected_hash, &sig)
            .expect("signature must verify at varint boundary");
    }

    #[test]
    fn test_deterministic() {
        let signer = ZcashSigner::mainnet();
        let addr1 = signer.derive_address(&test_privkey()).unwrap();
        let addr2 = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[cfg(feature = "zcash-shielded")]
    mod shielded_tests {
        use super::*;
        use crate::mnemonic::Mnemonic;

        const ABANDON_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        fn test_seed() -> Vec<u8> {
            let mnemonic = Mnemonic::from_phrase(ABANDON_PHRASE).unwrap();
            let seed = mnemonic.to_seed("");
            seed.expose().to_vec()
        }

        #[test]
        fn test_unified_address_mainnet() {
            let signer = ZcashSigner::mainnet();
            let seed = test_seed();
            let address = signer.derive_unified_address(&seed, 0).unwrap();
            assert!(
                address.starts_with("u1"),
                "mainnet unified address should start with u1, got: {}",
                address
            );
            assert!(
                address.len() > 50,
                "unified address should be long (has multiple receivers), got len: {}",
                address.len()
            );
        }

        #[test]
        fn test_unified_address_testnet() {
            let signer = ZcashSigner::testnet();
            let seed = test_seed();
            let address = signer.derive_unified_address(&seed, 0).unwrap();
            assert!(
                address.starts_with("utest1"),
                "testnet unified address should start with utest1, got: {}",
                address
            );
        }

        #[test]
        fn test_unified_address_deterministic() {
            let signer = ZcashSigner::mainnet();
            let seed = test_seed();
            let addr1 = signer.derive_unified_address(&seed, 0).unwrap();
            let addr2 = signer.derive_unified_address(&seed, 0).unwrap();
            assert_eq!(addr1, addr2);
        }

        #[test]
        fn test_unified_address_different_accounts() {
            let signer = ZcashSigner::mainnet();
            let seed = test_seed();
            let addr0 = signer.derive_unified_address(&seed, 0).unwrap();
            let addr1 = signer.derive_unified_address(&seed, 1).unwrap();
            assert_ne!(addr0, addr1, "different accounts must produce different addresses");
        }

        #[test]
        fn test_needs_raw_seed() {
            let signer = ZcashSigner::mainnet();
            assert!(signer.needs_raw_seed());
        }

        #[test]
        fn test_derive_address_from_seed_matches() {
            let signer = ZcashSigner::mainnet();
            let seed = test_seed();
            let addr_direct = signer.derive_unified_address(&seed, 0).unwrap();
            let addr_trait = signer.derive_address_from_seed(&seed, 0).unwrap();
            assert_eq!(addr_direct, addr_trait);
        }

        #[test]
        fn test_reject_short_seed() {
            let signer = ZcashSigner::mainnet();
            let short_seed = vec![0u8; 16];
            let result = signer.derive_unified_address(&short_seed, 0);
            assert!(result.is_err(), "should reject seed shorter than 32 bytes");
        }
    }
}
