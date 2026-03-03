"""Tests for the LWS client with mocked HTTP."""

from __future__ import annotations

import pytest
import httpx
import respx

from lws import (
    LWSClient,
    LWSClientSync,
    LwsError,
    LwsErrorCode,
    ChainType,
    MessageEncoding,
    TransactionStatus,
)

BASE = "http://127.0.0.1:8402"


# ---------------------------------------------------------------------------
# Async client tests
# ---------------------------------------------------------------------------


class TestLWSClientAsync:
    @respx.mock
    @pytest.mark.asyncio
    async def test_unlock(self):
        respx.post(f"{BASE}/v1/auth/unlock").mock(
            return_value=httpx.Response(200, json={"session_token": "lws_session_abc"})
        )
        async with LWSClient() as client:
            token = await client.unlock("my-passphrase")
            assert token == "lws_session_abc"
            # Verify the request body
            import json
            assert json.loads(respx.calls.last.request.content) == {"passphrase": "my-passphrase"}

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_wallets(self):
        wallets = [
            {
                "id": "w1",
                "name": "Wallet 1",
                "chains": ["evm"],
                "accounts": [],
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]
        respx.get(f"{BASE}/v1/wallets").mock(
            return_value=httpx.Response(200, json=wallets)
        )
        async with LWSClient(api_key="lws_key_test") as client:
            result = await client.list_wallets()
            assert len(result) == 1
            assert result[0].name == "Wallet 1"
            assert result[0].chains == [ChainType.EVM]
            # Verify auth header
            assert respx.calls.last.request.headers["Authorization"] == "Bearer lws_key_test"

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_wallets_with_filter(self):
        respx.get(f"{BASE}/v1/wallets").mock(
            return_value=httpx.Response(200, json=[])
        )
        async with LWSClient(api_key="lws_key_test") as client:
            await client.list_wallets(chain_type=ChainType.SOLANA)
            assert respx.calls.last.request.url.params["chain_type"] == "solana"

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_wallet(self):
        wallet = {
            "id": "w1",
            "name": "My Wallet",
            "chains": ["evm", "solana"],
            "accounts": [
                {
                    "chain": "eip155:1",
                    "address": "0xabc",
                    "derivation_path": "m/44'/60'/0'/0/0",
                    "account_id": "eip155:1:0xabc",
                }
            ],
            "created_at": "2024-01-01T00:00:00Z",
        }
        respx.get(f"{BASE}/v1/wallets/w1").mock(
            return_value=httpx.Response(200, json=wallet)
        )
        async with LWSClient(api_key="lws_key_test") as client:
            w = await client.get_wallet("w1")
            assert w.id == "w1"
            assert len(w.accounts) == 1
            assert w.accounts[0].address == "0xabc"

    @respx.mock
    @pytest.mark.asyncio
    async def test_create_wallet(self):
        wallet = {
            "id": "w-new",
            "name": "New Wallet",
            "chains": ["evm"],
            "accounts": [],
            "created_at": "2024-01-01T00:00:00Z",
        }
        respx.post(f"{BASE}/v1/wallets").mock(
            return_value=httpx.Response(201, json=wallet)
        )
        async with LWSClient(api_key="lws_key_test") as client:
            w = await client.create_wallet("New Wallet", [ChainType.EVM])
            assert w.id == "w-new"

    @respx.mock
    @pytest.mark.asyncio
    async def test_sign(self):
        respx.post(f"{BASE}/v1/wallets/w1/sign").mock(
            return_value=httpx.Response(200, json={"signed_transaction": "0xsigned"})
        )
        async with LWSClient(api_key="lws_key_test") as client:
            result = await client.sign("w1", "eip155:1", {"to": "0x123", "value": "100"})
            assert result.signed_transaction == "0xsigned"
            assert result.simulation is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_sign_and_send(self):
        respx.post(f"{BASE}/v1/wallets/w1/sign-and-send").mock(
            return_value=httpx.Response(200, json={
                "tx_hash": "0xtxhash",
                "status": "confirmed",
            })
        )
        async with LWSClient(api_key="lws_key_test") as client:
            result = await client.sign_and_send(
                "w1", "eip155:8453", {"to": "0x456", "value": "200"}
            )
            assert result.tx_hash == "0xtxhash"
            assert result.status == TransactionStatus.CONFIRMED

    @respx.mock
    @pytest.mark.asyncio
    async def test_sign_message(self):
        respx.post(f"{BASE}/v1/wallets/w1/sign-message").mock(
            return_value=httpx.Response(200, json={"signature": "0xsig"})
        )
        async with LWSClient(api_key="lws_key_test") as client:
            result = await client.sign_message(
                "w1", "eip155:1", "hello", encoding=MessageEncoding.UTF8
            )
            assert result.signature == "0xsig"

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_policy(self):
        policies = [{"id": "p1", "name": "limit", "executable": "/bin/policy"}]
        respx.get(f"{BASE}/v1/wallets/w1/policy").mock(
            return_value=httpx.Response(200, json=policies)
        )
        async with LWSClient(api_key="lws_key_test") as client:
            result = await client.get_policy("w1")
            assert len(result) == 1
            assert result[0].name == "limit"

    @respx.mock
    @pytest.mark.asyncio
    async def test_create_api_key(self):
        respx.post(f"{BASE}/v1/keys").mock(
            return_value=httpx.Response(201, json={
                "id": "k1",
                "name": "agent-key",
                "key_hash": "sha256abc",
                "scoped_wallets": ["w1"],
                "created_at": "2024-01-01T00:00:00Z",
                "key": "lws_key_newkey",
            })
        )
        async with LWSClient(api_key="lws_key_test") as client:
            key = await client.create_api_key("agent-key", ["w1"])
            assert key.key == "lws_key_newkey"

    @respx.mock
    @pytest.mark.asyncio
    async def test_list_api_keys(self):
        respx.get(f"{BASE}/v1/keys").mock(
            return_value=httpx.Response(200, json=[
                {
                    "id": "k1",
                    "name": "key1",
                    "key_hash": "h1",
                    "scoped_wallets": [],
                    "created_at": "2024-01-01T00:00:00Z",
                }
            ])
        )
        async with LWSClient(api_key="lws_key_test") as client:
            keys = await client.list_api_keys()
            assert len(keys) == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_get_api_key(self):
        respx.get(f"{BASE}/v1/keys/k1").mock(
            return_value=httpx.Response(200, json={
                "id": "k1",
                "name": "key1",
                "key_hash": "h1",
                "scoped_wallets": [],
                "created_at": "2024-01-01T00:00:00Z",
            })
        )
        async with LWSClient(api_key="lws_key_test") as client:
            key = await client.get_api_key("k1")
            assert key.id == "k1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_revoke_api_key(self):
        respx.delete(f"{BASE}/v1/keys/k1").mock(
            return_value=httpx.Response(204)
        )
        async with LWSClient(api_key="lws_key_test") as client:
            await client.revoke_api_key("k1")

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_handling(self):
        respx.get(f"{BASE}/v1/wallets/missing").mock(
            return_value=httpx.Response(404, json={
                "code": "WALLET_NOT_FOUND",
                "message": "wallet not found: missing",
            })
        )
        async with LWSClient(api_key="lws_key_test") as client:
            with pytest.raises(LwsError) as exc_info:
                await client.get_wallet("missing")
            err = exc_info.value
            assert err.code == LwsErrorCode.WALLET_NOT_FOUND
            assert err.message == "wallet not found: missing"
            assert err.status_code == 404

    @respx.mock
    @pytest.mark.asyncio
    async def test_policy_denied_error(self):
        respx.post(f"{BASE}/v1/wallets/w1/sign").mock(
            return_value=httpx.Response(403, json={
                "code": "POLICY_DENIED",
                "message": "policy denied: exceeds spending limit",
            })
        )
        async with LWSClient(api_key="lws_key_test") as client:
            with pytest.raises(LwsError) as exc_info:
                await client.sign("w1", "eip155:1", {"to": "0x123"})
            assert exc_info.value.code == LwsErrorCode.POLICY_DENIED

    @respx.mock
    @pytest.mark.asyncio
    async def test_unlock_sets_auth_header(self):
        respx.post(f"{BASE}/v1/auth/unlock").mock(
            return_value=httpx.Response(200, json={"session_token": "lws_session_xyz"})
        )
        respx.get(f"{BASE}/v1/wallets").mock(
            return_value=httpx.Response(200, json=[])
        )
        async with LWSClient() as client:
            await client.unlock("pass")
            await client.list_wallets()
            # After unlock, subsequent requests should use the session token
            assert "lws_session_xyz" in respx.calls.last.request.headers["Authorization"]


# ---------------------------------------------------------------------------
# Sync client tests
# ---------------------------------------------------------------------------


class TestLWSClientSync:
    @respx.mock
    def test_list_wallets(self):
        wallets = [
            {
                "id": "w1",
                "name": "Wallet 1",
                "chains": ["evm"],
                "accounts": [],
                "created_at": "2024-01-01T00:00:00Z",
            }
        ]
        respx.get(f"{BASE}/v1/wallets").mock(
            return_value=httpx.Response(200, json=wallets)
        )
        with LWSClientSync(api_key="lws_key_test") as client:
            result = client.list_wallets()
            assert len(result) == 1
            assert result[0].name == "Wallet 1"

    @respx.mock
    def test_error_handling(self):
        respx.get(f"{BASE}/v1/wallets/missing").mock(
            return_value=httpx.Response(404, json={
                "code": "WALLET_NOT_FOUND",
                "message": "wallet not found: missing",
            })
        )
        with LWSClientSync(api_key="lws_key_test") as client:
            with pytest.raises(LwsError) as exc_info:
                client.get_wallet("missing")
            assert exc_info.value.code == LwsErrorCode.WALLET_NOT_FOUND
