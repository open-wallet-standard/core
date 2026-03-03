"""LWS error types matching lws-core/src/error.rs."""

from __future__ import annotations

from enum import Enum


class LwsErrorCode(str, Enum):
    """Error codes returned by the LWS API."""

    WALLET_NOT_FOUND = "WALLET_NOT_FOUND"
    CHAIN_NOT_SUPPORTED = "CHAIN_NOT_SUPPORTED"
    POLICY_DENIED = "POLICY_DENIED"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    INVALID_PASSPHRASE = "INVALID_PASSPHRASE"
    VAULT_LOCKED = "VAULT_LOCKED"
    BROADCAST_FAILED = "BROADCAST_FAILED"
    TIMEOUT = "TIMEOUT"
    INVALID_INPUT = "INVALID_INPUT"
    CAIP_PARSE_ERROR = "CAIP_PARSE_ERROR"


class LwsError(Exception):
    """Exception raised for LWS API errors."""

    def __init__(self, code: str, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        try:
            self.code = LwsErrorCode(code)
        except ValueError:
            self.code = code  # type: ignore[assignment]
        self.message = message
        self.status_code = status_code

    def __repr__(self) -> str:
        code_val = self.code.value if isinstance(self.code, LwsErrorCode) else self.code
        return f"LwsError(code={code_val!r}, message={self.message!r})"

    @classmethod
    def from_response(cls, status_code: int, body: dict) -> LwsError:
        """Create an LwsError from an API error response body."""
        return cls(
            code=body.get("code", "UNKNOWN"),
            message=body.get("message", "Unknown error"),
            status_code=status_code,
        )
