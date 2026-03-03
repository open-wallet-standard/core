"""Tests for LWS type serialization round-trips and drift detection against lws-core."""

from __future__ import annotations

import re
from pathlib import Path

from lws.types import (
    AccountDescriptor,
    ApiKey,
    ChainType,
    MessageEncoding,
    Policy,
    SignAndSendResult,
    SignMessageResult,
    SignResult,
    SimulationResult,
    StateChange,
    StateChangeType,
    TransactionStatus,
    WalletDescriptor,
)

# ---------------------------------------------------------------------------
# Fixtures: representative dicts matching Rust serde output
# ---------------------------------------------------------------------------

WALLET_DICT = {
    "id": "3198bc9c-0001-4000-8000-000000000001",
    "name": "Test Wallet",
    "chains": ["evm", "solana"],
    "accounts": [
        {
            "chain": "eip155:1",
            "address": "0xabc123",
            "derivation_path": "m/44'/60'/0'/0/0",
            "account_id": "eip155:1:0xabc123",
        }
    ],
    "created_at": "2024-01-01T00:00:00Z",
}

SIGN_RESULT_DICT = {
    "signed_transaction": "0xdeadbeef",
    "simulation": {
        "success": True,
        "gas_estimate": 21000,
        "state_changes": [
            {
                "change_type": "balance_change",
                "address": "0x123",
                "amount": "-0.01",
            }
        ],
    },
}

SIGN_AND_SEND_RESULT_DICT = {
    "tx_hash": "0xabc123",
    "status": "confirmed",
    "simulation": None,
}

SIGN_MESSAGE_RESULT_DICT = {"signature": "0xsig456"}

POLICY_DICT = {
    "id": "p1",
    "name": "spending-limit",
    "executable": "/usr/local/bin/spending-policy",
    "timeout_ms": 5000,
}

API_KEY_DICT = {
    "id": "k1",
    "name": "agent-key",
    "key_hash": "sha256abc",
    "scoped_wallets": ["w1", "w2"],
    "created_at": "2024-01-01T00:00:00Z",
    "key": "lws_key_abc123",
}


# ---------------------------------------------------------------------------
# Round-trip serialization tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_chain_type_values(self):
        assert [c.value for c in ChainType] == ["evm", "solana", "cosmos", "bitcoin", "tron"]

    def test_message_encoding_values(self):
        assert [e.value for e in MessageEncoding] == ["utf8", "hex", "base64"]

    def test_transaction_status_values(self):
        assert [s.value for s in TransactionStatus] == ["pending", "confirmed", "failed"]

    def test_state_change_type_values(self):
        assert [t.value for t in StateChangeType] == [
            "balance_change",
            "token_transfer",
            "approval",
            "contract_call",
        ]


class TestWalletDescriptor:
    def test_round_trip(self):
        wallet = WalletDescriptor.from_dict(WALLET_DICT)
        assert wallet.id == "3198bc9c-0001-4000-8000-000000000001"
        assert wallet.name == "Test Wallet"
        assert wallet.chains == [ChainType.EVM, ChainType.SOLANA]
        assert len(wallet.accounts) == 1
        assert wallet.accounts[0].address == "0xabc123"
        assert wallet.updated_at is None
        # Round-trip: to_dict should not include updated_at when None
        d = wallet.to_dict()
        assert "updated_at" not in d
        assert WalletDescriptor.from_dict(d).id == wallet.id

    def test_with_updated_at(self):
        data = {**WALLET_DICT, "updated_at": "2024-06-01T00:00:00Z"}
        wallet = WalletDescriptor.from_dict(data)
        assert wallet.updated_at == "2024-06-01T00:00:00Z"
        assert wallet.to_dict()["updated_at"] == "2024-06-01T00:00:00Z"


class TestSignResult:
    def test_round_trip_with_simulation(self):
        result = SignResult.from_dict(SIGN_RESULT_DICT)
        assert result.signed_transaction == "0xdeadbeef"
        assert result.simulation is not None
        assert result.simulation.success is True
        assert result.simulation.gas_estimate == 21000
        assert len(result.simulation.state_changes) == 1
        sc = result.simulation.state_changes[0]
        assert sc.change_type == StateChangeType.BALANCE_CHANGE
        assert sc.amount == "-0.01"
        assert sc.token is None
        # Round-trip
        d = result.to_dict()
        assert d["signed_transaction"] == "0xdeadbeef"
        assert "error" not in d["simulation"]  # None fields omitted

    def test_without_simulation(self):
        result = SignResult.from_dict({"signed_transaction": "0xabc"})
        assert result.simulation is None
        assert "simulation" not in result.to_dict()


class TestSignAndSendResult:
    def test_round_trip(self):
        result = SignAndSendResult.from_dict(SIGN_AND_SEND_RESULT_DICT)
        assert result.tx_hash == "0xabc123"
        assert result.status == TransactionStatus.CONFIRMED
        assert result.simulation is None
        d = result.to_dict()
        assert d["status"] == "confirmed"
        assert "simulation" not in d


class TestSignMessageResult:
    def test_round_trip(self):
        result = SignMessageResult.from_dict(SIGN_MESSAGE_RESULT_DICT)
        assert result.signature == "0xsig456"
        assert result.to_dict() == SIGN_MESSAGE_RESULT_DICT


class TestPolicy:
    def test_round_trip(self):
        policy = Policy.from_dict(POLICY_DICT)
        assert policy.timeout_ms == 5000
        assert policy.to_dict() == POLICY_DICT

    def test_without_timeout(self):
        data = {k: v for k, v in POLICY_DICT.items() if k != "timeout_ms"}
        policy = Policy.from_dict(data)
        assert policy.timeout_ms is None
        assert "timeout_ms" not in policy.to_dict()


class TestApiKey:
    def test_round_trip(self):
        key = ApiKey.from_dict(API_KEY_DICT)
        assert key.scoped_wallets == ["w1", "w2"]
        assert key.key == "lws_key_abc123"
        d = key.to_dict()
        assert d["key"] == "lws_key_abc123"

    def test_without_optional_fields(self):
        data = {k: v for k, v in API_KEY_DICT.items() if k not in ("expires_at", "key")}
        key = ApiKey.from_dict(data)
        assert key.expires_at is None
        assert key.key is None
        d = key.to_dict()
        assert "expires_at" not in d
        assert "key" not in d


# ---------------------------------------------------------------------------
# Drift detection: ensure SDK types stay in sync with lws-core Rust source
# ---------------------------------------------------------------------------

CORE_ROOT = Path(__file__).resolve().parents[3] / "lws" / "crates" / "lws-core" / "src"


def _read_rust_file(name: str) -> str:
    """Read a Rust source file from lws-core, skip if not available."""
    path = CORE_ROOT / name
    if not path.exists():
        return ""
    return path.read_text()


class TestDriftDetection:
    """Verify SDK enum values and struct fields match the Rust source."""

    def test_chain_type_variants_match_rust(self):
        src = _read_rust_file("chain.rs")
        if not src:
            return
        # Extract enum variants from Rust source
        match = re.search(r"enum ChainType \{([^}]+)\}", src)
        assert match, "Could not find ChainType enum in chain.rs"
        variants = re.findall(r"(\w+)", match.group(1))
        rust_values = [v.lower() for v in variants]
        sdk_values = [c.value for c in ChainType]
        assert sdk_values == rust_values, (
            f"ChainType drift: SDK={sdk_values}, Rust={rust_values}"
        )

    def test_error_code_variants_match_rust(self):
        src = _read_rust_file("error.rs")
        if not src:
            return
        from lws.errors import LwsErrorCode

        match = re.search(r"enum LwsErrorCode \{([^}]+)\}", src)
        assert match, "Could not find LwsErrorCode enum in error.rs"
        variants = re.findall(r"(\w+)", match.group(1))
        # Rust uses SCREAMING_SNAKE_CASE via serde rename
        rust_codes = set()
        for v in variants:
            # Convert PascalCase to SCREAMING_SNAKE_CASE
            screaming = re.sub(r"(?<!^)(?=[A-Z])", "_", v).upper()
            rust_codes.add(screaming)
        sdk_codes = {c.value for c in LwsErrorCode}
        assert sdk_codes == rust_codes, (
            f"LwsErrorCode drift: SDK={sdk_codes}, Rust={rust_codes}"
        )

    def test_message_encoding_variants_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"enum MessageEncoding \{([^}]+)\}", src)
        assert match, "Could not find MessageEncoding enum in types.rs"
        variants = re.findall(r"(\w+)", match.group(1))
        rust_values = [v.lower() for v in variants]
        sdk_values = [e.value for e in MessageEncoding]
        assert sdk_values == rust_values, (
            f"MessageEncoding drift: SDK={sdk_values}, Rust={rust_values}"
        )

    def test_transaction_status_variants_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"enum TransactionStatus \{([^}]+)\}", src)
        assert match, "Could not find TransactionStatus enum in types.rs"
        variants = re.findall(r"(\w+)", match.group(1))
        rust_values = [v.lower() for v in variants]
        sdk_values = [s.value for s in TransactionStatus]
        assert sdk_values == rust_values, (
            f"TransactionStatus drift: SDK={sdk_values}, Rust={rust_values}"
        )

    def test_state_change_type_variants_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"enum StateChangeType \{([^}]+)\}", src)
        assert match, "Could not find StateChangeType enum in types.rs"
        variants = re.findall(r"(\w+)", match.group(1))
        # Rust uses snake_case via serde rename
        rust_values = [re.sub(r"(?<!^)(?=[A-Z])", "_", v).lower() for v in variants]
        sdk_values = [t.value for t in StateChangeType]
        assert sdk_values == rust_values, (
            f"StateChangeType drift: SDK={sdk_values}, Rust={rust_values}"
        )

    def test_wallet_descriptor_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct WalletDescriptor \{([^}]+)\}", src)
        assert match, "Could not find WalletDescriptor struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(WalletDescriptor.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"WalletDescriptor drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_account_descriptor_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct AccountDescriptor \{([^}]+)\}", src)
        assert match, "Could not find AccountDescriptor struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(AccountDescriptor.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"AccountDescriptor drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_sign_result_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct SignResult \{([^}]+)\}", src)
        assert match, "Could not find SignResult struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(SignResult.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"SignResult drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_sign_and_send_result_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct SignAndSendResult \{([^}]+)\}", src)
        assert match, "Could not find SignAndSendResult struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(SignAndSendResult.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"SignAndSendResult drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_simulation_result_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct SimulationResult \{([^}]+)\}", src)
        assert match, "Could not find SimulationResult struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(SimulationResult.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"SimulationResult drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_state_change_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct StateChange \{([^}]+)\}", src)
        assert match, "Could not find StateChange struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(StateChange.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"StateChange drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_policy_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct Policy \{([^}]+)\}", src)
        assert match, "Could not find Policy struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(Policy.__dataclass_fields__.keys())
        assert sdk_fields == rust_fields, (
            f"Policy drift: SDK={sdk_fields}, Rust={rust_fields}"
        )

    def test_api_key_fields_match_rust(self):
        src = _read_rust_file("types.rs")
        if not src:
            return
        match = re.search(r"struct ApiKey \{([^}]+)\}", src)
        assert match, "Could not find ApiKey struct in types.rs"
        rust_fields = set(re.findall(r"pub (\w+):", match.group(1)))
        sdk_fields = set(ApiKey.__dataclass_fields__.keys())
        # SDK has an extra 'key' field for the raw key returned at creation
        assert rust_fields.issubset(sdk_fields), (
            f"ApiKey drift — Rust fields missing from SDK: {rust_fields - sdk_fields}"
        )

    def test_rest_endpoints_match_spec(self):
        """Verify the spec file lists the expected REST endpoints."""
        spec_path = Path(__file__).resolve().parents[3] / "docs" / "06-agent-access-layer.md"
        if not spec_path.exists():
            return
        spec = spec_path.read_text()
        expected_endpoints = [
            "POST /v1/wallets",
            "GET  /v1/wallets",
            "GET  /v1/wallets/:id",
            "POST /v1/wallets/:id/sign",
            "POST /v1/wallets/:id/sign-and-send",
            "POST /v1/wallets/:id/sign-message",
            "GET  /v1/wallets/:id/policy",
            "POST   /v1/keys",
            "GET    /v1/keys",
            "GET    /v1/keys/:id",
            "DELETE /v1/keys/:id",
        ]
        for endpoint in expected_endpoints:
            # Normalize whitespace for matching
            normalized = " ".join(endpoint.split())
            pattern = re.escape(normalized).replace(r"\ ", r"\s+")
            assert re.search(pattern, spec), (
                f"Endpoint {normalized!r} not found in spec"
            )
