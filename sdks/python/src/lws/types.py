"""LWS type definitions matching lws-core/src/types.rs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChainType(str, Enum):
    """Blockchain type identifier."""

    EVM = "evm"
    SOLANA = "solana"
    COSMOS = "cosmos"
    BITCOIN = "bitcoin"
    TRON = "tron"


class MessageEncoding(str, Enum):
    """Message encoding for sign-message requests."""

    UTF8 = "utf8"
    HEX = "hex"
    BASE64 = "base64"


class TransactionStatus(str, Enum):
    """Status of a submitted transaction."""

    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"


class StateChangeType(str, Enum):
    """Type of state change from simulation."""

    BALANCE_CHANGE = "balance_change"
    TOKEN_TRANSFER = "token_transfer"
    APPROVAL = "approval"
    CONTRACT_CALL = "contract_call"


@dataclass
class AccountDescriptor:
    """An account derived from a wallet on a specific chain."""

    chain: str
    address: str
    derivation_path: str
    account_id: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccountDescriptor:
        return cls(
            chain=data["chain"],
            address=data["address"],
            derivation_path=data["derivation_path"],
            account_id=data["account_id"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain": self.chain,
            "address": self.address,
            "derivation_path": self.derivation_path,
            "account_id": self.account_id,
        }


@dataclass
class WalletDescriptor:
    """High-level wallet descriptor."""

    id: str
    name: str
    chains: list[ChainType]
    accounts: list[AccountDescriptor]
    created_at: str
    updated_at: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WalletDescriptor:
        return cls(
            id=data["id"],
            name=data["name"],
            chains=[ChainType(c) for c in data["chains"]],
            accounts=[AccountDescriptor.from_dict(a) for a in data.get("accounts", [])],
            created_at=data["created_at"],
            updated_at=data.get("updated_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "chains": [c.value for c in self.chains],
            "accounts": [a.to_dict() for a in self.accounts],
            "created_at": self.created_at,
        }
        if self.updated_at is not None:
            d["updated_at"] = self.updated_at
        return d


@dataclass
class StateChange:
    """A state change from simulation."""

    change_type: StateChangeType
    address: str
    amount: str | None = None
    token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StateChange:
        return cls(
            change_type=StateChangeType(data["change_type"]),
            address=data["address"],
            amount=data.get("amount"),
            token=data.get("token"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "change_type": self.change_type.value,
            "address": self.address,
        }
        if self.amount is not None:
            d["amount"] = self.amount
        if self.token is not None:
            d["token"] = self.token
        return d


@dataclass
class SimulationResult:
    """Simulation result for a transaction."""

    success: bool
    state_changes: list[StateChange]
    gas_estimate: int | None = None
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SimulationResult:
        return cls(
            success=data["success"],
            state_changes=[StateChange.from_dict(s) for s in data.get("state_changes", [])],
            gas_estimate=data.get("gas_estimate"),
            error=data.get("error"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "success": self.success,
            "state_changes": [s.to_dict() for s in self.state_changes],
        }
        if self.gas_estimate is not None:
            d["gas_estimate"] = self.gas_estimate
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class SignResult:
    """Result of signing a transaction."""

    signed_transaction: str
    simulation: SimulationResult | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignResult:
        sim = data.get("simulation")
        return cls(
            signed_transaction=data["signed_transaction"],
            simulation=SimulationResult.from_dict(sim) if sim else None,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"signed_transaction": self.signed_transaction}
        if self.simulation is not None:
            d["simulation"] = self.simulation.to_dict()
        return d


@dataclass
class SignAndSendResult:
    """Result of sign-and-send."""

    tx_hash: str
    status: TransactionStatus
    simulation: SimulationResult | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignAndSendResult:
        sim = data.get("simulation")
        return cls(
            tx_hash=data["tx_hash"],
            status=TransactionStatus(data["status"]),
            simulation=SimulationResult.from_dict(sim) if sim else None,
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tx_hash": self.tx_hash,
            "status": self.status.value,
        }
        if self.simulation is not None:
            d["simulation"] = self.simulation.to_dict()
        return d


@dataclass
class SignMessageResult:
    """Result of signing a message."""

    signature: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignMessageResult:
        return cls(signature=data["signature"])

    def to_dict(self) -> dict[str, Any]:
        return {"signature": self.signature}


@dataclass
class Policy:
    """Policy definition."""

    id: str
    name: str
    executable: str
    timeout_ms: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(
            id=data["id"],
            name=data["name"],
            executable=data["executable"],
            timeout_ms=data.get("timeout_ms"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "executable": self.executable,
        }
        if self.timeout_ms is not None:
            d["timeout_ms"] = self.timeout_ms
        return d


@dataclass
class ApiKey:
    """API key descriptor."""

    id: str
    name: str
    key_hash: str
    scoped_wallets: list[str]
    created_at: str
    expires_at: str | None = None
    key: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApiKey:
        return cls(
            id=data["id"],
            name=data["name"],
            key_hash=data["key_hash"],
            scoped_wallets=data.get("scoped_wallets", []),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            key=data.get("key"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "key_hash": self.key_hash,
            "scoped_wallets": self.scoped_wallets,
            "created_at": self.created_at,
        }
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        if self.key is not None:
            d["key"] = self.key
        return d
