"""LWS REST API client — async-first with sync wrapper."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .errors import LwsError
from .types import (
    ApiKey,
    ChainType,
    MessageEncoding,
    Policy,
    SignAndSendResult,
    SignMessageResult,
    SignResult,
    WalletDescriptor,
)

DEFAULT_BASE_URL = "http://127.0.0.1:8402"


class LWSClient:
    """Async LWS REST API client.

    Usage::

        async with LWSClient(api_key="lws_key_...") as client:
            wallets = await client.list_wallets()
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = 30.0,
    ) -> None:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=timeout,
        )

    # -- internal helpers --

    def _auth_headers(self, token: str | None = None) -> dict[str, str]:
        """Build auth headers, preferring an explicit token over the default key."""
        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
        token: str | None = None,
    ) -> Any:
        """Send a request and return parsed JSON, raising LwsError on failure."""
        response = await self._http.request(
            method,
            path,
            json=json,
            params=params,
            headers=self._auth_headers(token),
        )
        if response.status_code == 204:
            return None
        body = response.json()
        if response.status_code >= 400:
            raise LwsError.from_response(response.status_code, body)
        return body

    # -- auth --

    async def unlock(self, passphrase: str) -> str:
        """Unlock the vault and return a session token."""
        data = await self._request("POST", "/v1/auth/unlock", json={"passphrase": passphrase})
        token: str = data["session_token"]
        # Update default auth to use the session token
        self._http.headers["Authorization"] = f"Bearer {token}"
        return token

    # -- wallets --

    async def list_wallets(self, chain_type: ChainType | None = None) -> list[WalletDescriptor]:
        """List all wallets visible to the caller."""
        params = {}
        if chain_type is not None:
            params["chain_type"] = chain_type.value
        data = await self._request("GET", "/v1/wallets", params=params or None)
        return [WalletDescriptor.from_dict(w) for w in data]

    async def get_wallet(self, wallet_id: str) -> WalletDescriptor:
        """Get a wallet descriptor by ID."""
        data = await self._request("GET", f"/v1/wallets/{wallet_id}")
        return WalletDescriptor.from_dict(data)

    async def create_wallet(
        self,
        name: str,
        chains: list[ChainType],
    ) -> WalletDescriptor:
        """Create a new wallet (owner only)."""
        data = await self._request(
            "POST",
            "/v1/wallets",
            json={"name": name, "chains": [c.value for c in chains]},
        )
        return WalletDescriptor.from_dict(data)

    # -- signing --

    async def sign(
        self,
        wallet_id: str,
        chain_id: str,
        transaction: dict[str, Any],
        *,
        simulate: bool = True,
    ) -> SignResult:
        """Sign a transaction."""
        data = await self._request(
            "POST",
            f"/v1/wallets/{wallet_id}/sign",
            json={
                "chain": chain_id,
                "transaction": transaction,
                "simulate": simulate,
            },
        )
        return SignResult.from_dict(data)

    async def sign_and_send(
        self,
        wallet_id: str,
        chain_id: str,
        transaction: dict[str, Any],
        *,
        simulate: bool = True,
        max_retries: int = 3,
        confirmations: int = 1,
    ) -> SignAndSendResult:
        """Sign and broadcast a transaction."""
        data = await self._request(
            "POST",
            f"/v1/wallets/{wallet_id}/sign-and-send",
            json={
                "chain": chain_id,
                "transaction": transaction,
                "simulate": simulate,
                "max_retries": max_retries,
                "confirmations": confirmations,
            },
        )
        return SignAndSendResult.from_dict(data)

    async def sign_message(
        self,
        wallet_id: str,
        chain_id: str,
        message: str,
        *,
        encoding: MessageEncoding | None = None,
    ) -> SignMessageResult:
        """Sign an arbitrary message."""
        body: dict[str, Any] = {
            "chain": chain_id,
            "message": message,
        }
        if encoding is not None:
            body["encoding"] = encoding.value
        data = await self._request(
            "POST",
            f"/v1/wallets/{wallet_id}/sign-message",
            json=body,
        )
        return SignMessageResult.from_dict(data)

    # -- policies --

    async def get_policy(self, wallet_id: str) -> list[Policy]:
        """Get the caller's policies for a wallet."""
        data = await self._request("GET", f"/v1/wallets/{wallet_id}/policy")
        return [Policy.from_dict(p) for p in data]

    # -- API keys (owner only) --

    async def create_api_key(
        self,
        name: str,
        wallet_ids: list[str],
        *,
        expires_at: str | None = None,
        policies: list[str] | None = None,
    ) -> ApiKey:
        """Create a new API key (owner only)."""
        body: dict[str, Any] = {
            "name": name,
            "wallet_ids": wallet_ids,
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        if policies is not None:
            body["policies"] = policies
        data = await self._request("POST", "/v1/keys", json=body)
        return ApiKey.from_dict(data)

    async def list_api_keys(self) -> list[ApiKey]:
        """List all API keys (owner only)."""
        data = await self._request("GET", "/v1/keys")
        return [ApiKey.from_dict(k) for k in data]

    async def get_api_key(self, key_id: str) -> ApiKey:
        """Get API key details (owner only)."""
        data = await self._request("GET", f"/v1/keys/{key_id}")
        return ApiKey.from_dict(data)

    async def revoke_api_key(self, key_id: str) -> None:
        """Revoke an API key (owner only)."""
        await self._request("DELETE", f"/v1/keys/{key_id}")

    # -- lifecycle --

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

    async def __aenter__(self) -> LWSClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class LWSClientSync:
    """Synchronous wrapper around LWSClient.

    Usage::

        with LWSClientSync(api_key="lws_key_...") as client:
            wallets = client.list_wallets()
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        *,
        timeout: float = 30.0,
    ) -> None:
        self._loop = asyncio.new_event_loop()
        self._client = LWSClient(api_key=api_key, base_url=base_url, timeout=timeout)

    def _run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def unlock(self, passphrase: str) -> str:
        return self._run(self._client.unlock(passphrase))

    def list_wallets(self, chain_type: ChainType | None = None) -> list[WalletDescriptor]:
        return self._run(self._client.list_wallets(chain_type))

    def get_wallet(self, wallet_id: str) -> WalletDescriptor:
        return self._run(self._client.get_wallet(wallet_id))

    def create_wallet(self, name: str, chains: list[ChainType]) -> WalletDescriptor:
        return self._run(self._client.create_wallet(name, chains))

    def sign(
        self,
        wallet_id: str,
        chain_id: str,
        transaction: dict[str, Any],
        *,
        simulate: bool = True,
    ) -> SignResult:
        return self._run(self._client.sign(wallet_id, chain_id, transaction, simulate=simulate))

    def sign_and_send(
        self,
        wallet_id: str,
        chain_id: str,
        transaction: dict[str, Any],
        *,
        simulate: bool = True,
        max_retries: int = 3,
        confirmations: int = 1,
    ) -> SignAndSendResult:
        return self._run(
            self._client.sign_and_send(
                wallet_id,
                chain_id,
                transaction,
                simulate=simulate,
                max_retries=max_retries,
                confirmations=confirmations,
            )
        )

    def sign_message(
        self,
        wallet_id: str,
        chain_id: str,
        message: str,
        *,
        encoding: MessageEncoding | None = None,
    ) -> SignMessageResult:
        return self._run(
            self._client.sign_message(wallet_id, chain_id, message, encoding=encoding)
        )

    def get_policy(self, wallet_id: str) -> list[Policy]:
        return self._run(self._client.get_policy(wallet_id))

    def create_api_key(
        self,
        name: str,
        wallet_ids: list[str],
        *,
        expires_at: str | None = None,
        policies: list[str] | None = None,
    ) -> ApiKey:
        return self._run(
            self._client.create_api_key(name, wallet_ids, expires_at=expires_at, policies=policies)
        )

    def list_api_keys(self) -> list[ApiKey]:
        return self._run(self._client.list_api_keys())

    def get_api_key(self, key_id: str) -> ApiKey:
        return self._run(self._client.get_api_key(key_id))

    def revoke_api_key(self, key_id: str) -> None:
        self._run(self._client.revoke_api_key(key_id))

    def close(self) -> None:
        self._run(self._client.close())
        self._loop.close()

    def __enter__(self) -> LWSClientSync:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
