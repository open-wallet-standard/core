#![doc = include_str!("../README.md")]

use std::{fmt, path::PathBuf, sync::Arc};

use alloy_consensus::SignableTransaction;
use alloy_dyn_abi::{eip712::Resolver, DynSolValue, TypedData};
use alloy_network::{TxSigner, TxSignerSync};
use alloy_primitives::{Address, ChainId, Signature, B256, U256};
use alloy_signer::{Error, Result, Signer, SignerSync};
use alloy_sol_types::{Eip712Domain, SolStruct};
use async_trait::async_trait;
use zeroize::Zeroizing;

struct Wallet {
    id: String,
    address: Address,
    index: u32,
    credential: Zeroizing<String>,
    vault_path: PathBuf,
    policy_chain_id: ChainId,
}

/// An Alloy signer for one stored OWS EVM account.
///
/// Clones share a zeroizing credential buffer, not private keys. Construction
/// reads public metadata; credentials are authenticated on every signing call.
/// Async methods offload blocking vault/KDF/policy work to a Tokio runtime.
#[derive(Clone)]
pub struct OwsSigner {
    wallet: Arc<Wallet>,
    chain_id: Option<ChainId>,
}

impl fmt::Debug for OwsSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwsSigner")
            .field("wallet_id", &self.wallet.id)
            .field("address", &self.wallet.address)
            .field("index", &self.wallet.index)
            .field("chain_id", &self.chain_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl OwsSigner {
    /// Select a wallet by name or ID and its stored EVM account.
    ///
    /// `credential` is the owner password (explicitly `""` if empty) or an OWS
    /// API token. `policy_chain_id` is the chain context for hashes/messages/
    /// typed data, and the initial transaction chain ID. Transactions always
    /// use their actual nonzero chain ID for policy evaluation.
    pub fn new(
        name_or_id: &str,
        credential: String,
        policy_chain_id: ChainId,
        vault_path: Option<PathBuf>,
    ) -> Result<Self> {
        let credential = Zeroizing::new(credential);
        if policy_chain_id == 0 {
            return Err(Error::other("OWS requires a nonzero EVM chain ID"));
        }
        let vault_path = ows_lib::vault::resolve_vault_path(vault_path.as_deref());
        let info = ows_lib::get_wallet(name_or_id, Some(&vault_path)).map_err(Error::other)?;
        let vault_path = vault_path.canonicalize().map_err(Error::other)?;
        let account = info
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with("eip155:"))
            .ok_or_else(|| Error::other("wallet has no stored EVM account"))?;
        let index = if account.derivation_path.is_empty() {
            0 // Imported private-key wallet.
        } else {
            account
                .derivation_path
                .strip_prefix("m/44'/60'/0'/0/")
                .and_then(|suffix| suffix.parse::<u32>().ok())
                .filter(|index| *index < (1 << 31))
                .ok_or_else(|| Error::other("unsupported stored EVM derivation path"))?
        };
        let address = account.address.parse().map_err(Error::other)?;
        Ok(Self {
            wallet: Arc::new(Wallet {
                id: info.id,
                address,
                index,
                credential,
                vault_path,
                policy_chain_id,
            }),
            chain_id: Some(policy_chain_id),
        })
    }

    /// The public address selected from the stored account.
    pub fn address(&self) -> Address {
        self.wallet.address
    }

    /// Chain context for operations which have no transaction chain ID.
    pub fn policy_chain_id(&self) -> ChainId {
        self.wallet.policy_chain_id
    }

    fn chain(&self) -> String {
        format!("eip155:{}", self.wallet.policy_chain_id)
    }

    fn checked_signature(&self, result: ows_lib::SignResult, hash: &B256) -> Result<Signature> {
        let bytes = hex::decode(result.signature).map_err(Error::other)?;
        let signature = Signature::try_from(bytes.as_slice()).map_err(Error::other)?;
        if signature
            .recover_address_from_prehash(hash)
            .map_err(Error::other)?
            != self.address()
        {
            return Err(Error::other(
                "signature does not match the stored OWS account",
            ));
        }
        Ok(signature)
    }

    fn prepare_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<(ChainId, Vec<u8>, B256)> {
        if let Some(chain_id) = self.chain_id {
            if !tx.set_chain_id_checked(chain_id) {
                return Err(Error::other(
                    "transaction chain ID differs from signer chain ID",
                ));
            }
        }
        let chain_id = tx.chain_id().filter(|id| *id != 0).ok_or_else(|| {
            Error::other("OWS requires replay-protected transactions with a nonzero chain ID")
        })?;
        Ok((chain_id, tx.encoded_for_signing(), tx.signature_hash()))
    }

    fn sign_transaction_bytes(
        &self,
        chain_id: ChainId,
        bytes: &[u8],
        hash: &B256,
    ) -> Result<Signature> {
        let result = ows_lib::sign_transaction(
            &self.wallet.id,
            &format!("eip155:{chain_id}"),
            &hex::encode(bytes),
            Some(&self.wallet.credential),
            Some(self.wallet.index),
            Some(&self.wallet.vault_path),
        )
        .map_err(Error::other)?;
        self.checked_signature(result, hash)
    }

    async fn blocking<F>(work: F) -> Result<Signature>
    where
        F: FnOnce() -> Result<Signature> + Send + 'static,
    {
        let runtime = tokio::runtime::Handle::try_current().map_err(Error::other)?;
        runtime.spawn_blocking(work).await.map_err(Error::other)?
    }
}

impl SignerSync for OwsSigner {
    fn sign_hash_sync(&self, hash: &B256) -> Result<Signature> {
        let result = ows_lib::sign_hash(
            &self.wallet.id,
            &self.chain(),
            &hex::encode(hash),
            Some(&self.wallet.credential),
            Some(self.wallet.index),
            Some(&self.wallet.vault_path),
        )
        .map_err(Error::other)?;
        self.checked_signature(result, hash)
    }

    fn sign_message_sync(&self, message: &[u8]) -> Result<Signature> {
        let result = ows_lib::sign_message(
            &self.wallet.id,
            &self.chain(),
            &hex::encode(message),
            Some(&self.wallet.credential),
            Some("hex"),
            Some(self.wallet.index),
            Some(&self.address().to_string()),
            Some(&self.wallet.vault_path),
        )
        .map_err(Error::other)?;
        self.checked_signature(result, &alloy_primitives::eip191_hash_message(message))
    }

    fn sign_typed_data_sync<T: SolStruct>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> Result<Signature> {
        self.sign_dynamic_typed_data_sync(&typed_data(payload, domain)?)
    }

    fn sign_dynamic_typed_data_sync(&self, payload: &TypedData) -> Result<Signature> {
        if payload
            .domain
            .chain_id
            .is_some_and(|id| id != U256::from(self.policy_chain_id()))
        {
            return Err(Error::other(
                "typed-data domain chain ID differs from OWS policy chain",
            ));
        }
        let hash = payload.eip712_signing_hash().map_err(Error::other)?;
        let mut document = serde_json::to_value(payload).map_err(Error::other)?;
        // Alloy hashes the domain from its concrete fields, independently of
        // the supplied types map. OWS needs the matching domain type explicitly.
        let mut resolver = payload.resolver.clone();
        resolver
            .ingest_string(payload.domain.encode_type())
            .map_err(Error::other)?;
        document["types"] = serde_json::to_value(resolver).map_err(Error::other)?;
        // OWS accepts full-width integer words; Alloy's quantity hex can have
        // odd digits and OWS decimal parsing is limited to 128 bits. Preserve
        // the full integer range with padded words, including signed values.
        document["message"] = if payload.primary_type == "EIP712Domain" {
            // Alloy's domain-only requests do not sign the message at all.
            // Omit unsigned fields from the policy payload as well.
            serde_json::json!({})
        } else {
            json_value(payload.coerce().map_err(Error::other)?, true)?
        };
        if let Some(chain_id) = payload.domain.chain_id {
            document["domain"]["chainId"] = chain_id.to_string().into();
        }
        let json = serde_json::to_string(&document).map_err(Error::other)?;
        let result = ows_lib::sign_typed_data(
            &self.wallet.id,
            &self.chain(),
            &json,
            Some(&self.wallet.credential),
            Some(self.wallet.index),
            Some(&self.address().to_string()),
            Some(&self.wallet.vault_path),
        )
        .map_err(Error::other)?;
        self.checked_signature(result, &hash)
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id
    }
}

impl TxSignerSync<Signature> for OwsSigner {
    fn address(&self) -> Address {
        self.address()
    }

    fn sign_transaction_sync(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        let (chain_id, bytes, hash) = self.prepare_transaction(tx)?;
        self.sign_transaction_bytes(chain_id, &bytes, &hash)
    }
}

#[async_trait]
impl Signer for OwsSigner {
    async fn sign_hash(&self, hash: &B256) -> Result<Signature> {
        let this = self.clone();
        let hash = *hash;
        Self::blocking(move || this.sign_hash_sync(&hash)).await
    }

    async fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let this = self.clone();
        let message = message.to_vec();
        Self::blocking(move || this.sign_message_sync(&message)).await
    }

    async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> Result<Signature> {
        self.sign_dynamic_typed_data(&typed_data(payload, domain)?)
            .await
    }

    async fn sign_dynamic_typed_data(&self, payload: &TypedData) -> Result<Signature> {
        let this = self.clone();
        let payload = payload.clone();
        Self::blocking(move || this.sign_dynamic_typed_data_sync(&payload)).await
    }

    fn address(&self) -> Address {
        self.address()
    }
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

// Alloy's SolStruct trait does not require serde::Serialize. Recover named
// fields through its ABI schema/encoding so generic typed-data calls still give
// OWS policies the full message rather than just a precomputed digest.
fn typed_data<T: SolStruct>(payload: &T, domain: &Eip712Domain) -> Result<TypedData> {
    let mut resolver = Resolver::default();
    resolver
        .ingest_string(T::eip712_encode_type())
        .map_err(Error::other)?;
    resolver
        .ingest_string(domain.encode_type())
        .map_err(Error::other)?;
    fn encode<S: alloy_sol_types::SolType>(value: &S::RustType) -> Vec<u8> {
        S::abi_encode(value)
    }
    let value = resolver
        .resolve(T::NAME)
        .map_err(Error::other)?
        .abi_decode(&encode::<T>(payload))
        .map_err(Error::other)?;
    let data = TypedData {
        domain: domain.clone(),
        resolver,
        primary_type: T::NAME.into(),
        message: json_value(value, false)?,
    };
    if data.eip712_signing_hash().map_err(Error::other)? != payload.eip712_signing_hash(domain) {
        return Err(Error::other(
            "typed-data ABI conversion changed the signing hash",
        ));
    }
    Ok(data)
}

fn json_value(value: DynSolValue, integer_words: bool) -> Result<serde_json::Value> {
    use serde_json::Value;
    Ok(match value {
        DynSolValue::Bool(value) => Value::Bool(value),
        DynSolValue::Int(value, _) => Value::String(if integer_words {
            format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
        } else {
            value.to_string()
        }),
        DynSolValue::Uint(value, _) => Value::String(if integer_words {
            format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
        } else {
            value.to_string()
        }),
        DynSolValue::FixedBytes(value, len) => {
            Value::String(format!("0x{}", hex::encode(&value[..len])))
        }
        DynSolValue::Address(value) => Value::String(value.to_string()),
        DynSolValue::Bytes(value) => Value::String(format!("0x{}", hex::encode(value))),
        DynSolValue::String(value) => Value::String(value),
        DynSolValue::Array(values) | DynSolValue::FixedArray(values) => Value::Array(
            values
                .into_iter()
                .map(|value| json_value(value, integer_words))
                .collect::<Result<_>>()?,
        ),
        DynSolValue::CustomStruct {
            prop_names, tuple, ..
        } => Value::Object(
            prop_names
                .into_iter()
                .zip(tuple)
                .map(|(name, value)| json_value(value, integer_words).map(|value| (name, value)))
                .collect::<Result<_>>()?,
        ),
        _ => return Err(Error::other("unsupported EIP-712 field type")),
    })
}

#[async_trait]
impl TxSigner<Signature> for OwsSigner {
    fn address(&self) -> Address {
        self.address()
    }

    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> Result<Signature> {
        // Move only public bytes/hash to the worker, not the borrowed trait object.
        let (chain_id, bytes, hash) = self.prepare_transaction(tx)?;
        let this = self.clone();
        Self::blocking(move || this.sign_transaction_bytes(chain_id, &bytes, &hash)).await
    }
}
