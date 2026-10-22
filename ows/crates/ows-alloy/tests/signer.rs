use std::path::Path;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy};
use alloy_dyn_abi::TypedData;
use alloy_network::{Ethereum, EthereumWallet, NetworkWallet, TxSigner, TxSignerSync};
use alloy_primitives::{address, Address, Bytes, Signature, TxKind, B256, U256};
use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{eip712_domain, sol};
use ows_alloy::OwsSigner;

const KEY: &str = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const OWNER: &str = "test-only-owner-password";
const CONTRACT: Address = address!("1111111111111111111111111111111111111111");

// Deliberately no Serialize derive: Alloy's generic Signer contract does not
// require it. Named fields must still reach OWS's typed-data policy operation.
sol! {
    struct Person { string name; address wallet; }
    struct Message {
        Person from;
        Person[] to;
        string contents;
        uint256 amount;
        int256 adjustment;
        bytes payload;
        bytes4 selector;
        uint8[2] flags;
        bool approved;
    }
    struct Matrix {
        uint256[][] values;
        Person[2][] people;
    }
}

fn message() -> Message {
    Message {
        from: Person {
            name: "Alice".into(),
            wallet: CONTRACT,
        },
        to: vec![Person {
            name: "Bob".into(),
            wallet: Address::ZERO,
        }],
        contents: "Hello 🔒".into(),
        amount: U256::MAX,
        adjustment: alloy_primitives::I256::try_from(-42).unwrap(),
        payload: Bytes::from(vec![0, 255, 17]),
        selector: [1, 2, 3, 4].into(),
        flags: [0, 255],
        approved: true,
    }
}

fn domain() -> alloy_sol_types::Eip712Domain {
    eip712_domain! { name: "OWS test", version: "1", chain_id: 1, verifying_contract: CONTRACT, }
}

fn nested_data() -> TypedData {
    serde_json::from_value(serde_json::json!({
        "types": {
            "Matrix": [{"name":"values", "type":"uint256[][]"}, {"name":"people", "type":"Person[2][]"}],
            "Person": [{"name":"name", "type":"string"}, {"name":"wallet", "type":"address"}]
        },
        "domain": domain(), "primaryType": "Matrix",
        "message": {
            "values": [[U256::MAX.to_string(), "1"], [], ["2"]],
            "people": [[{"name":"Alice", "wallet":CONTRACT}, {"name":"Bob", "wallet":Address::ZERO}]]
        }
    })).unwrap()
}

#[tokio::test]
async fn multidimensional_integer_and_struct_arrays_match_alloy() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    let value = Matrix {
        values: vec![vec![U256::MAX, U256::from(1)], vec![], vec![U256::from(2)]],
        people: vec![[
            Person {
                name: "Alice".into(),
                wallet: CONTRACT,
            },
            Person {
                name: "Bob".into(),
                wallet: Address::ZERO,
            },
        ]],
    };
    let domain = domain();
    let expected = local().sign_typed_data_sync(&value, &domain).unwrap();
    assert_eq!(
        signer.sign_typed_data_sync(&value, &domain).unwrap(),
        expected
    );
    assert_eq!(
        signer.sign_typed_data(&value, &domain).await.unwrap(),
        expected
    );
    let data = nested_data();
    assert_eq!(
        local().sign_dynamic_typed_data_sync(&data).unwrap(),
        expected
    );
    assert_eq!(
        signer.sign_dynamic_typed_data_sync(&data).unwrap(),
        expected
    );
    assert_eq!(
        signer.sign_dynamic_typed_data(&data).await.unwrap(),
        expected
    );
}

#[tokio::test]
async fn domain_only_typed_data_matches_alloy_without_a_message() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    for domain in [
        serde_json::json!({}),
        serde_json::to_value(domain()).unwrap(),
    ] {
        let data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {}, "domain": domain, "primaryType": "EIP712Domain",
            // These properties are unsigned and must not be coerced as a struct.
            "message": {"unsigned": "ignored"}
        }))
        .unwrap();
        let expected = local().sign_dynamic_typed_data_sync(&data).unwrap();
        assert_eq!(
            signer.sign_dynamic_typed_data_sync(&data).unwrap(),
            expected
        );
        assert_eq!(
            signer.sign_dynamic_typed_data(&data).await.unwrap(),
            expected
        );
    }
}

fn fixture(vault: &Path, credential: &str) -> OwsSigner {
    ows_lib::import_wallet_private_key(
        "fixture",
        KEY,
        Some("ethereum"),
        Some(OWNER),
        Some(vault),
        None,
        None,
        None,
    )
    .unwrap();
    OwsSigner::new("fixture", credential.into(), 1, Some(vault.into())).unwrap()
}

fn local() -> PrivateKeySigner {
    KEY.parse().unwrap()
}

fn transaction(chain_id: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id,
        nonce: 7,
        gas_limit: 50_000,
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(CONTRACT),
        value: U256::from(123456789),
        input: Bytes::from(vec![0, 255, 42]),
        ..Default::default()
    }
}

#[tokio::test]
async fn hashes_binary_messages_and_typed_data_match_alloy_local_signer() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    let local = local();
    assert_eq!(signer.address(), local.address());
    let hash = B256::repeat_byte(42);
    let bytes = [0, 255, 17, 128];
    assert_eq!(
        signer.sign_hash_sync(&hash).unwrap(),
        local.sign_hash_sync(&hash).unwrap()
    );
    assert_eq!(
        signer.sign_hash(&hash).await.unwrap(),
        local.sign_hash(&hash).await.unwrap()
    );
    assert_eq!(
        signer.sign_message_sync(&bytes).unwrap(),
        local.sign_message_sync(&bytes).unwrap()
    );
    assert_eq!(
        signer.sign_message(&bytes).await.unwrap(),
        local.sign_message(&bytes).await.unwrap()
    );
    let value = message();
    let domain = domain();
    let expected = local.sign_typed_data_sync(&value, &domain).unwrap();
    assert_eq!(
        signer.sign_typed_data_sync(&value, &domain).unwrap(),
        expected
    );
    assert_eq!(
        signer.sign_typed_data(&value, &domain).await.unwrap(),
        expected
    );
    let dynamic: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"EIP712Domain": [], "Value": [{"name":"amount", "type":"uint256"}]},
        "domain": {}, "primaryType": "Value", "message": {"amount": "123456789012345678901234567890"}
    })).unwrap();
    for adjustment in [alloy_primitives::I256::MIN, alloy_primitives::I256::MAX] {
        let mut value = message();
        value.adjustment = adjustment;
        value.to.clear();
        value.payload = Bytes::new();
        value.contents.clear();
        assert_eq!(
            signer.sign_typed_data_sync(&value, &domain).unwrap(),
            local.sign_typed_data_sync(&value, &domain).unwrap()
        );
    }
    let expected = local.sign_dynamic_typed_data_sync(&dynamic).unwrap();
    assert_eq!(
        signer.sign_dynamic_typed_data_sync(&dynamic).unwrap(),
        expected
    );
    assert_eq!(
        signer.sign_dynamic_typed_data(&dynamic).await.unwrap(),
        expected
    );
    let dynamic_without_domain_type: TypedData = serde_json::from_value(serde_json::json!({
        "types": {"Value": [{"name":"amount", "type":"uint256"}]},
        "domain": {"name":"OWS test", "chainId":"0x1"},
        "primaryType": "Value", "message": {"amount": "0xf"}
    }))
    .unwrap();
    assert_eq!(
        signer
            .sign_dynamic_typed_data_sync(&dynamic_without_domain_type)
            .unwrap(),
        local
            .sign_dynamic_typed_data_sync(&dynamic_without_domain_type)
            .unwrap()
    );
}

#[test]
fn legacy_and_typed_transactions_match_alloy() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    let reference = local().with_chain_id(Some(1));
    let transactions: Vec<Box<dyn SignableTransaction<Signature>>> = vec![
        Box::new(TxLegacy {
            nonce: 2,
            gas_limit: 21_000,
            gas_price: 123,
            to: TxKind::Call(CONTRACT),
            ..Default::default()
        }),
        Box::new(TxEip2930 {
            chain_id: 1,
            ..Default::default()
        }),
        Box::new(transaction(1)),
        Box::new(TxEip4844 {
            chain_id: 1,
            ..Default::default()
        }),
        Box::new(TxEip7702 {
            chain_id: 1,
            ..Default::default()
        }),
    ];
    for mut tx in transactions {
        let actual = signer.sign_transaction_sync(tx.as_mut()).unwrap();
        assert_eq!(tx.chain_id(), Some(1));
        let expected = reference.sign_transaction_sync(tx.as_mut()).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            actual
                .recover_address_from_prehash(&tx.signature_hash())
                .unwrap(),
            signer.address()
        );
    }
}

#[tokio::test]
async fn ethereum_wallet_signs_a_complete_envelope_offline() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    let address = signer.address();
    let wallet = EthereumWallet::new(signer.clone());
    assert!(NetworkWallet::<Ethereum>::has_signer_for(&wallet, &address));
    let tx = transaction(1);
    let hash = tx.signature_hash();
    let envelope = NetworkWallet::<Ethereum>::sign_transaction(&wallet, tx.into())
        .await
        .unwrap();
    assert_eq!(
        envelope
            .signature()
            .recover_address_from_prehash(&hash)
            .unwrap(),
        address
    );
    let mut tx = transaction(1);
    let actual = TxSigner::sign_transaction(&signer, &mut tx).await.unwrap();
    assert_eq!(&actual, envelope.signature());
    let wrong_sender = Address::ZERO;
    assert!(NetworkWallet::<Ethereum>::sign_transaction_from(
        &wallet,
        wrong_sender,
        transaction(1).into()
    )
    .await
    .is_err());
}

#[test]
fn replay_protection_and_chain_configuration_are_explicit() {
    let vault = tempfile::tempdir().unwrap();
    let mut signer = fixture(vault.path(), OWNER);
    let mut wrong_chain = transaction(8453);
    assert!(signer.sign_transaction_sync(&mut wrong_chain).is_err());
    assert_eq!(wrong_chain.chain_id, 8453);
    assert_eq!(Signer::chain_id(&signer), Some(1));
    assert_eq!(signer.chain_id_sync(), Some(1));
    signer.set_chain_id(None);
    assert_eq!(signer.policy_chain_id(), 1);
    assert!(signer.sign_transaction_sync(&mut wrong_chain).is_ok());
    assert!(signer
        .sign_transaction_sync(&mut TxLegacy::default())
        .is_err());
    assert!(signer.sign_transaction_sync(&mut transaction(0)).is_err());
    signer.set_chain_id(Some(0));
    assert!(signer.sign_transaction_sync(&mut transaction(0)).is_err());
    let mut wrong_domain = domain();
    wrong_domain.chain_id = Some(U256::from(8453));
    assert!(signer
        .sign_typed_data_sync(&message(), &wrong_domain)
        .is_err());
}

#[test]
fn mnemonic_index_and_renamed_wallet_remain_bound_to_stored_identity() {
    let vault = tempfile::tempdir().unwrap();
    let info = ows_lib::import_wallet_mnemonic("mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        Some(OWNER), Some(3), Some(vault.path())).unwrap();
    let signer = OwsSigner::new("mnemonic", OWNER.into(), 1, Some(vault.path().into())).unwrap();
    let address: Address = info
        .accounts
        .iter()
        .find(|a| a.chain_id.starts_with("eip155:"))
        .unwrap()
        .address
        .parse()
        .unwrap();
    assert_eq!(signer.address(), address);
    ows_lib::rename_wallet(&info.id, "renamed", Some(vault.path())).unwrap();
    let hash = B256::repeat_byte(7);
    assert_eq!(
        signer
            .sign_hash_sync(&hash)
            .unwrap()
            .recover_address_from_prehash(&hash)
            .unwrap(),
        address
    );
    let debug = format!("{signer:?}");
    assert!(!debug.contains(OWNER));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn wrong_credentials_missing_wallet_and_metadata_mismatch_return_errors() {
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), "wrong-password");
    assert!(signer.sign_hash_sync(&B256::ZERO).is_err());
    assert!(OwsSigner::new("missing", OWNER.into(), 1, Some(vault.path().into())).is_err());
    assert!(OwsSigner::new("fixture", OWNER.into(), 0, Some(vault.path().into())).is_err());
    let info = ows_lib::get_wallet("fixture", Some(vault.path())).unwrap();
    let path = vault
        .path()
        .join("wallets")
        .join(format!("{}.json", info.id));
    let mut data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    data["accounts"][0]["address"] = CONTRACT.to_string().into();
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    let signer = OwsSigner::new("fixture", OWNER.into(), 1, Some(vault.path().into())).unwrap();
    assert!(signer
        .sign_hash_sync(&B256::ZERO)
        .unwrap_err()
        .to_string()
        .contains("stored OWS account"));
    data["accounts"][0]["derivation_path"] = "m/44'/60'/1'/0/0".into();
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(OwsSigner::new("fixture", OWNER.into(), 1, Some(vault.path().into())).is_err());
    data["accounts"] = serde_json::json!([]);
    std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
    assert!(OwsSigner::new("fixture", OWNER.into(), 1, Some(vault.path().into())).is_err());
}

#[test]
fn async_signing_without_tokio_returns_an_error_instead_of_panicking() {
    use std::{
        future::Future,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };
    struct Noop;
    impl Wake for Noop {
        fn wake(self: Arc<Self>) {}
    }
    let vault = tempfile::tempdir().unwrap();
    let signer = fixture(vault.path(), OWNER);
    let hash = B256::ZERO;
    let mut future = Box::pin(signer.sign_hash(&hash));
    let waker = Waker::from(Arc::new(Noop));
    assert!(matches!(
        future.as_mut().poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(_))
    ));
}

#[test]
fn api_keys_are_scoped_by_wallet_id_even_for_identical_addresses() {
    let vault = tempfile::tempdir().unwrap();
    let owner = fixture(vault.path(), OWNER);
    let info = ows_lib::get_wallet("fixture", Some(vault.path())).unwrap();
    let (token, _) = ows_lib::key_ops::create_api_key(
        "scoped",
        &[info.id],
        &[],
        OWNER,
        None,
        Some(vault.path()),
    )
    .unwrap();
    let permitted = OwsSigner::new("fixture", token.clone(), 1, Some(vault.path().into())).unwrap();
    assert!(permitted.sign_hash_sync(&B256::ZERO).is_ok());
    ows_lib::import_wallet_private_key(
        "outside-scope",
        KEY,
        Some("ethereum"),
        Some(OWNER),
        Some(vault.path()),
        None,
        None,
        None,
    )
    .unwrap();
    let denied = OwsSigner::new("outside-scope", token, 1, Some(vault.path().into())).unwrap();
    assert_eq!(denied.address(), owner.address());
    assert!(denied.sign_hash_sync(&B256::ZERO).is_err());
    assert!(denied.sign_message_sync(b"offline").is_err());
    assert!(denied.sign_typed_data_sync(&message(), &domain()).is_err());
    assert!(denied.sign_transaction_sync(&mut transaction(1)).is_err());
}

#[cfg(unix)]
mod policies {
    use super::*;
    use ows_core::{Policy, PolicyAction, PolicyRule};
    use std::os::unix::fs::PermissionsExt;

    fn agent(vault: &Path, reject_hash: bool) -> (OwsSigner, String) {
        let _owner = fixture(vault, OWNER);
        let script = vault.join("policy.py");
        std::fs::write(
            &script,
            format!(
                r##"#!/usr/bin/env python3
import json, pathlib, sys
context = json.load(sys.stdin)
pathlib.Path(__file__).with_name('context.json').write_text(json.dumps(context))
print(json.dumps({{"allow": not ({} and context["request_type"] == "sign_hash")}}))
"##,
                if reject_hash { "True" } else { "False" }
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            id: "adapter-policy".into(),
            name: "Adapter test".into(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".into(),
            rules: vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:1".into()],
                },
                PolicyRule::AllowedTypedDataContracts {
                    contracts: vec![CONTRACT.to_string()],
                },
            ],
            executable: Some(script.to_string_lossy().into()),
            config: None,
            action: PolicyAction::Deny,
        };
        ows_lib::policy_store::save_policy(&policy, Some(vault)).unwrap();
        let info = ows_lib::get_wallet("fixture", Some(vault)).unwrap();
        let (token, key) = ows_lib::key_ops::create_api_key(
            "agent",
            &[info.id],
            &[policy.id],
            OWNER,
            None,
            Some(vault),
        )
        .unwrap();
        let signer = OwsSigner::new("fixture", token, 1, Some(vault.into())).unwrap();
        (signer, key.id)
    }

    fn context(vault: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(vault.join("context.json")).unwrap()).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_policy_does_not_stall_the_async_executor() {
        let vault = tempfile::tempdir().unwrap();
        let (signer, _) = agent(vault.path(), false);
        let path = vault.path().join("policy.py");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            path,
            source.replace(
                "print(json.dumps",
                // Wait for the async test to release the policy. A bounded
                // watchdog lets a regression fail instead of hanging forever.
                r#"import time
release = pathlib.Path(__file__).with_name('release')
deadline = time.monotonic() + 10
while not release.exists():
    if time.monotonic() > deadline:
        sys.exit(1)
    time.sleep(0.01)
print(json.dumps"#,
            ),
        )
        .unwrap();
        let task = tokio::spawn(async move { signer.sign_message(b"offline").await });
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !vault.path().join("context.json").exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("policy did not start");
        assert!(
            !task.is_finished(),
            "blocking policy work stalled the single-thread runtime"
        );
        std::fs::write(vault.path().join("release"), "continue").unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn agent_calls_preserve_operation_and_full_policy_payloads() {
        let vault = tempfile::tempdir().unwrap();
        let (signer, _) = agent(vault.path(), false);
        let hash = B256::repeat_byte(42);
        signer.sign_hash(&hash).await.unwrap();
        assert_eq!(context(vault.path())["request_type"], "sign_hash");
        assert_eq!(
            context(vault.path())["transaction"]["raw_hex"],
            hex::encode(hash)
        );
        signer.sign_message(&[0, 255, 17]).await.unwrap();
        assert_eq!(context(vault.path())["request_type"], "sign_message");
        assert_eq!(context(vault.path())["transaction"]["raw_hex"], "00ff11");
        signer.sign_typed_data(&message(), &domain()).await.unwrap();
        let ctx = context(vault.path());
        assert_eq!(ctx["request_type"], "sign_typed_data");
        let raw: serde_json::Value =
            serde_json::from_str(ctx["typed_data"]["raw_json"].as_str().unwrap()).unwrap();
        assert_eq!(raw["primaryType"], "Message");
        assert_eq!(raw["message"]["from"]["name"], "Alice");
        assert_eq!(raw["message"]["amount"], format!("0x{}", "ff".repeat(32)));
        assert_eq!(
            raw["message"]["adjustment"],
            format!("0x{}d6", "ff".repeat(31))
        );
        let mut tx = transaction(1);
        let bytes = tx.encoded_for_signing();
        TxSigner::sign_transaction(&signer, &mut tx).await.unwrap();
        let ctx = context(vault.path());
        assert_eq!(ctx["request_type"], "sign_transaction");
        assert_eq!(ctx["transaction"]["raw_hex"], hex::encode(bytes));
    }

    #[tokio::test]
    async fn nested_arrays_and_domain_only_data_preserve_typed_policy_routing() {
        let vault = tempfile::tempdir().unwrap();
        // The policy rejects raw hashes, so a digest fallback would fail.
        let (signer, _) = agent(vault.path(), true);
        let data = nested_data();
        let expected = local().sign_dynamic_typed_data_sync(&data).unwrap();
        assert_eq!(
            signer.sign_dynamic_typed_data(&data).await.unwrap(),
            expected
        );
        let ctx = context(vault.path());
        assert_eq!(ctx["request_type"], "sign_typed_data");
        let raw: serde_json::Value =
            serde_json::from_str(ctx["typed_data"]["raw_json"].as_str().unwrap()).unwrap();
        assert_eq!(raw["message"]["people"][0][0]["name"], "Alice");
        assert_eq!(
            raw["message"]["values"][0][0],
            format!("0x{}", "ff".repeat(32))
        );
        let data: TypedData = serde_json::from_value(serde_json::json!({
            "types": {}, "domain": domain(), "primaryType": "EIP712Domain",
            "message": {"unsigned": "ignored"}
        }))
        .unwrap();
        let expected = local().sign_dynamic_typed_data_sync(&data).unwrap();
        assert_eq!(
            signer.sign_dynamic_typed_data(&data).await.unwrap(),
            expected
        );
        let ctx = context(vault.path());
        assert_eq!(ctx["request_type"], "sign_typed_data");
        let raw: serde_json::Value =
            serde_json::from_str(ctx["typed_data"]["raw_json"].as_str().unwrap()).unwrap();
        assert_eq!(raw["primaryType"], "EIP712Domain");
        assert_eq!(raw["domain"]["name"], "OWS test");
        assert_eq!(raw["message"], serde_json::json!({}));
    }

    #[test]
    fn agent_chain_contract_revocation_and_hash_denials_are_preserved() {
        let vault = tempfile::tempdir().unwrap();
        let (mut signer, key_id) = agent(vault.path(), true);
        assert!(signer.sign_hash_sync(&B256::ZERO).is_err());
        assert!(signer.sign_message_sync(b"offline").is_ok());
        assert!(signer.sign_typed_data_sync(&message(), &domain()).is_ok());
        let mut other_contract = domain();
        other_contract.verifying_contract = Some(Address::ZERO);
        assert!(signer
            .sign_typed_data_sync(&message(), &other_contract)
            .is_err());
        signer.set_chain_id(None);
        assert!(signer
            .sign_transaction_sync(&mut transaction(8453))
            .is_err());
        assert!(signer.sign_transaction_sync(&mut transaction(1)).is_ok());
        ows_lib::key_store::delete_api_key(&key_id, Some(vault.path())).unwrap();
        assert!(signer.sign_message_sync(b"offline").is_err());
        assert!(signer.sign_typed_data_sync(&message(), &domain()).is_err());
        assert!(signer.sign_transaction_sync(&mut transaction(1)).is_err());
    }
}
