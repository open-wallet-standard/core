"""Tests for ows Python bindings."""

import copy
import json
import tempfile
import pytest
import ows


@pytest.fixture
def vault_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_generate_mnemonic_12():
    phrase = ows.generate_mnemonic(12)
    assert len(phrase.split()) == 12


def test_generate_mnemonic_24():
    phrase = ows.generate_mnemonic(24)
    assert len(phrase.split()) == 24


def test_derive_address_evm():
    phrase = ows.generate_mnemonic(12)
    # "evm" still works via backward compat
    address = ows.derive_address(phrase, "evm")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_ethereum():
    phrase = ows.generate_mnemonic(12)
    address = ows.derive_address(phrase, "ethereum")
    assert address.startswith("0x")
    assert len(address) == 42


def test_derive_address_all_supported_chains():
    phrase = ows.generate_mnemonic(12)
    for chain in ["evm", "solana", "sui", "bitcoin", "cosmos", "tron", "ton", "filecoin", "xrpl", "nano", "near", "cardano"]:
        address = ows.derive_address(phrase, chain)
        assert len(address) > 0


def test_create_and_list_wallets(vault_dir):
    wallet = ows.create_wallet("test-wallet", vault_path_opt=vault_dir)
    assert wallet["name"] == "test-wallet"
    assert isinstance(wallet["accounts"], list)
    assert len(wallet["accounts"]) == 16

    # Verify each chain family is present
    chain_ids = [a["chain_id"] for a in wallet["accounts"]]
    assert any(c.startswith("eip155:") for c in chain_ids)
    assert any(c.startswith("solana:") for c in chain_ids)
    assert any(c.startswith("sui:") for c in chain_ids)
    assert any(c.startswith("bip122:") for c in chain_ids)
    assert any(c.startswith("cosmos:") for c in chain_ids)
    assert any(c.startswith("tron:") for c in chain_ids)
    assert any(c.startswith("ton:") for c in chain_ids)
    assert any(c.startswith("spark:") for c in chain_ids)
    assert any(c.startswith("fil:") for c in chain_ids)
    assert any(c.startswith("xrpl:") for c in chain_ids)
    assert any(c.startswith("nano:") for c in chain_ids)
    assert any(c.startswith("near:") for c in chain_ids)
    assert any(c.startswith("cip34:") for c in chain_ids)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 1
    assert wallets[0]["id"] == wallet["id"]


def test_get_wallet(vault_dir):
    wallet = ows.create_wallet("lookup", vault_path_opt=vault_dir)

    found = ows.get_wallet("lookup", vault_path_opt=vault_dir)
    assert found["id"] == wallet["id"]

    found = ows.get_wallet(wallet["id"], vault_path_opt=vault_dir)
    assert found["name"] == "lookup"


def test_rename_wallet(vault_dir):
    ows.create_wallet("old-name", vault_path_opt=vault_dir)
    ows.rename_wallet("old-name", "new-name", vault_path_opt=vault_dir)

    found = ows.get_wallet("new-name", vault_path_opt=vault_dir)
    assert found["name"] == "new-name"


def test_export_wallet(vault_dir):
    ows.create_wallet("exportable", vault_path_opt=vault_dir)
    secret = ows.export_wallet("exportable", vault_path_opt=vault_dir)
    assert len(secret.split()) == 12


def test_delete_wallet(vault_dir):
    wallet = ows.create_wallet("deletable", vault_path_opt=vault_dir)
    ows.delete_wallet("deletable", vault_path_opt=vault_dir)

    wallets = ows.list_wallets(vault_path_opt=vault_dir)
    assert len(wallets) == 0


def test_import_wallet_mnemonic(vault_dir):
    phrase = ows.generate_mnemonic(12)
    expected_addr = ows.derive_address(phrase, "ethereum")

    wallet = ows.import_wallet_mnemonic(
        "imported", phrase, vault_path_opt=vault_dir
    )
    assert wallet["name"] == "imported"
    assert len(wallet["accounts"]) == 16

    # EVM account should match derived address
    evm_account = next(a for a in wallet["accounts"] if a["chain_id"].startswith("eip155:"))
    assert evm_account["address"] == expected_addr


def test_sign_transaction(vault_dir):
    ows.create_wallet("signer", vault_path_opt=vault_dir)

    tx_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    result = ows.sign_transaction(
        "signer", "evm", tx_hex, vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None


def test_sign_message(vault_dir):
    ows.create_wallet("msg-signer", vault_path_opt=vault_dir)

    result = ows.sign_message(
        "msg-signer", "evm", "hello world", vault_path_opt=vault_dir
    )
    assert len(result["signature"]) > 0


def test_sign_hash_and_authorization_owner_mode(vault_dir):
    wallet = ows.create_wallet("hash-owner", vault_path_opt=vault_dir)

    hash_result = ows.sign_hash(
        wallet["id"], "base", "11" * 32, vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0
    assert hash_result["recovery_id"] in (0, 1)

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0
    assert auth_result["recovery_id"] in (0, 1)


def test_sign_hash_and_authorization_api_key_mode(vault_dir):
    wallet = ows.create_wallet("hash-agent", vault_path_opt=vault_dir)

    ows.create_policy(
        """{
          "id": "base-only-hash",
          "name": "Base Only Hash",
          "version": 1,
          "created_at": "2026-03-22T00:00:00Z",
          "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]}
          ],
          "action": "deny"
        }""",
        vault_path_opt=vault_dir,
    )

    key = ows.create_api_key(
        "hash-agent-key",
        [wallet["id"]],
        ["base-only-hash"],
        "",
        vault_path_opt=vault_dir,
    )

    hash_result = ows.sign_hash(
        wallet["id"], "base", "22" * 32, key["token"], vault_path_opt=vault_dir
    )
    assert len(hash_result["signature"]) > 0

    auth_result = ows.sign_authorization(
        wallet["id"],
        "base",
        "0x1111111111111111111111111111111111111111",
        "7",
        key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(auth_result["signature"]) > 0

    with pytest.raises(RuntimeError, match="not in allowlist"):
        ows.sign_authorization(
            wallet["id"],
            "ethereum",
            "0x1111111111111111111111111111111111111111",
            "7",
            key["token"],
            vault_path_opt=vault_dir,
        )


NEAR_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
NEP413_SIGNATURE = (
    "c76b8fd211f7545b9d3fb863ad38d9bb7fdb31521eea65e13efcf67a48ccbaef"
    "0e54c64ae2dd4fd6b8f28dba6463468487ec846e3b1e252588dfbedf0a86a709"
)


def test_sign_nep413_message_owner_mode(vault_dir):
    wallet = ows.import_wallet_private_key(
        "nep413-owner", NEAR_SEED, chain="near", vault_path_opt=vault_dir
    )

    result = ows.sign_nep413_message(
        wallet["id"],
        "near",
        "Sign in to example.com",
        "42" * 32,
        "example.com",
        callback_url="https://example.com/callback",
        vault_path_opt=vault_dir,
    )
    assert result["signature"] == NEP413_SIGNATURE
    assert result["recovery_id"] is None

    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        ows.sign_nep413_message(
            wallet["id"], "near", "hi", "42" * 31, "example.com",
            vault_path_opt=vault_dir,
        )
    with pytest.raises(RuntimeError, match="only supported for NEAR chains"):
        ows.sign_nep413_message(
            wallet["id"], "solana", "hi", "42" * 32, "example.com",
            vault_path_opt=vault_dir,
        )


def test_sign_nep413_message_api_key_mode(vault_dir):
    wallet = ows.import_wallet_private_key(
        "nep413-agent", NEAR_SEED, chain="near", vault_path_opt=vault_dir
    )
    ows.create_policy(json.dumps({
        "id": "near-mainnet-only",
        "name": "NEAR Mainnet Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [{"type": "allowed_chains", "chain_ids": ["near:mainnet"]}],
        "action": "deny",
    }), vault_path_opt=vault_dir)
    key = ows.create_api_key(
        "nep413-agent-key", [wallet["id"]], ["near-mainnet-only"], "",
        vault_path_opt=vault_dir,
    )

    result = ows.sign_nep413_message(
        wallet["id"],
        "near",
        "Sign in to example.com",
        "42" * 32,
        "example.com",
        callback_url="https://example.com/callback",
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )
    assert result["signature"] == NEP413_SIGNATURE

    with pytest.raises(RuntimeError, match="not in allowlist"):
        ows.sign_nep413_message(
            wallet["id"], "near-testnet", "Sign in to example.com", "42" * 32,
            "example.com", passphrase=key["token"], vault_path_opt=vault_dir,
        )


NEP366_FT_TRANSFER = (
    "400000006437356139383031383262313061623764353462666564336339363430373361306565313732663364616136323332356166303231613638"
    "66373037353131610f00000066742e6578616d706c652e6e65617201000000020b00000066745f7472616e736665723a0000007b2272656365697665"
    "725f6964223a226d65726368616e742e6578616d706c652e6e656172222c22616d6f756e74223a2231303030303030227d00e057eb481b0000010000"
    "000000000000000000000000002a0000000000000000e1f5050000000000d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
NEP366_FT_TRANSFER_SIGNATURE = (
    "b01b4df30474223b0892e3bc1fe7b8fb9362b8783e89017be2e9a4bbc88d9c90"
    "54e6f33067c97fc2de71602b54844990cc72c382a23b1a5e0a1390b9b72c4200"
)


def test_sign_delegate_action_owner_mode(vault_dir):
    wallet = ows.import_wallet_private_key(
        "nep366-owner", NEAR_SEED, chain="near", vault_path_opt=vault_dir
    )

    result = ows.sign_delegate_action(
        wallet["id"], "near", NEP366_FT_TRANSFER, vault_path_opt=vault_dir
    )
    assert result["signature"] == NEP366_FT_TRANSFER_SIGNATURE
    assert result["recovery_id"] is None

    with pytest.raises(RuntimeError, match="NEP-366 delegate action"):
        ows.sign_delegate_action(
            wallet["id"], "near", NEP366_FT_TRANSFER[:-2], vault_path_opt=vault_dir
        )
    with pytest.raises(RuntimeError, match="only supported for NEAR chains"):
        ows.sign_delegate_action(
            wallet["id"], "solana", NEP366_FT_TRANSFER, vault_path_opt=vault_dir
        )


def test_sign_typed_data_with_api_key(vault_dir):
    wallet = ows.create_wallet("td-api-test", vault_path_opt=vault_dir)

    # Register a policy allowing Base chains
    ows.create_policy(json.dumps({
        "id": "td-base-only",
        "name": "Base Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"]},
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    # Create API key bound to the wallet and policy
    key = ows.create_api_key(
        "td-agent", [wallet["id"]], ["td-base-only"], "",
        vault_path_opt=vault_dir,
    )
    assert key["token"].startswith("ows_key_")

    # EIP-712 typed data (the standard "Mail" example)
    typed_data_json = json.dumps({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"},
            ],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!",
        },
    })

    # Sign on allowed chain -- should succeed
    result = ows.sign_typed_data(
        wallet["id"], "base", typed_data_json,
        passphrase=key["token"], vault_path_opt=vault_dir,
    )
    assert len(result["signature"]) > 0
    assert result["recovery_id"] is not None

    # Sign on denied chain -- should fail
    # Build typed data with chainId=1 matching ethereum so the domain check passes
    # and AllowedChains (base-only) correctly denies
    eth_td = copy.deepcopy(json.loads(typed_data_json))
    eth_td["domain"]["chainId"] = 1
    eth_typed_data_json = json.dumps(eth_td)
    with pytest.raises(Exception, match="not in allowlist"):
        ows.sign_typed_data(
            wallet["id"], "ethereum", eth_typed_data_json,
            passphrase=key["token"], vault_path_opt=vault_dir,
        )

    # Cleanup
    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-base-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)


def test_sign_typed_data_respects_allowed_typed_data_contracts(vault_dir):
    wallet = ows.create_wallet("td-contract-test", vault_path_opt=vault_dir)

    ows.create_policy(json.dumps({
        "id": "td-contract-only",
        "name": "Typed Data Contract Only",
        "version": 1,
        "created_at": "2026-03-22T00:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]},
            {
                "type": "allowed_typed_data_contracts",
                "contracts": ["0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"],
            },
        ],
        "action": "deny",
    }), vault_path_opt=vault_dir)

    key = ows.create_api_key(
        "td-contract-agent",
        [wallet["id"]],
        ["td-contract-only"],
        "",
        vault_path_opt=vault_dir,
    )

    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Mail": [{"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 8453,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        },
        "message": {
            "contents": "Hello, Bob!",
        },
    }

    allowed = ows.sign_typed_data(
        wallet["id"],
        "base",
        json.dumps(typed_data),
        passphrase=key["token"],
        vault_path_opt=vault_dir,
    )
    assert len(allowed["signature"]) > 0

    denied_typed_data = copy.deepcopy(typed_data)
    denied_typed_data["domain"]["verifyingContract"] = "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"

    with pytest.raises(Exception, match="not in allowed list"):
        ows.sign_typed_data(
            wallet["id"],
            "base",
            json.dumps(denied_typed_data),
            passphrase=key["token"],
            vault_path_opt=vault_dir,
        )

    ows.revoke_api_key(key["id"], vault_path_opt=vault_dir)
    ows.delete_policy("td-contract-only", vault_path_opt=vault_dir)
    ows.delete_wallet(wallet["id"], vault_path_opt=vault_dir)
