from __future__ import annotations

import argparse
import ast
import asyncio
import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from tools.acceptance import outcome_acceptance
from tools.acceptance.outcome_acceptance import (
    ACTION_SCHEMA_VERSION,
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    OPERATION_TIMEOUT_SECONDS,
    REPORT_VERSION,
    REQUIRED_TOOLS,
    AcceptanceFailure,
    DiscoveryAttemptFailure,
    _action,
    _call,
    _config,
    _discover,
    run,
)

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "tools" / "acceptance"


def test_external_acceptance_package_has_no_outcome_imports() -> None:
    forbidden = {
        "authorization",
        "verification",
        "policies",
        "billing",
        "ledger",
        "receipts",
        "execution",
        "providers",
        "db",
    }
    for path in ACCEPTANCE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    parts = name.split(".")
                    assert not (
                        parts[0] == "outcome" and (len(parts) == 1 or parts[1] in forbidden)
                    )


def test_safe_action_is_bounded_and_non_external() -> None:
    action = _action()
    assert action == {
        "action_type": "controlled_beta_test",
        "capability": "authorize",
        "amount_micro_usd": 0,
        "currency": "USD",
        "destination": "synthetic-resource",
        "operation": "record-test-marker",
        "resource": "synthetic-resource",
    }
    assert ACTION_SCHEMA_VERSION == "action.material.v1"


def test_acceptance_contract_versions_and_required_discovery() -> None:
    assert REPORT_VERSION == "outcome.controlled-beta-acceptance.v1"
    assert REQUIRED_TOOLS == {
        "outcome_verify",
        "outcome_authorize",
        "outcome_capabilities",
        "outcome_execute_authorized",
    }


def test_remote_mode_requires_all_configuration_and_redacts_cli_error() -> None:
    completed = subprocess.run(
        [str(ROOT / ".venv/bin/python"), "-m", "tools.acceptance.outcome_acceptance"],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "OUTCOME_MCP_URL" in completed.stderr
    assert "oc_agent_" not in completed.stderr


def test_report_shape_contains_no_secret(tmp_path: Path) -> None:
    secret = "oc_agent_sentinel_never_emit"
    report = {
        "acceptance_schema_version": REPORT_VERSION,
        "overall_status": "FAIL",
        "failed_stage": "authentication",
        "reason_codes": ["AUTHENTICATION_FAILED"],
    }
    encoded = json.dumps(report)
    assert secret not in encoded
    assert set(report) >= {"acceptance_schema_version", "overall_status", "reason_codes"}


def _config_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["outcome-acceptance"])
    monkeypatch.setenv("OUTCOME_MCP_URL", "https://example.test/mcp")
    monkeypatch.setenv("OUTCOME_API_KEY", "oc_agent_test_secret")
    monkeypatch.setenv("OUTCOME_ACCEPTANCE_POLICY_ID", "policy")
    monkeypatch.setenv("OUTCOME_ACCEPTANCE_VERIFICATION_RESULT_ID", "verification")


def test_discovery_timeout_defaults_to_30_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    _config_environment(monkeypatch)
    monkeypatch.delenv("OUTCOME_ACCEPTANCE_DISCOVERY_TIMEOUT_SECONDS", raising=False)
    assert _config().discovery_timeout_seconds == DEFAULT_DISCOVERY_TIMEOUT_SECONDS == 30.0
    assert OPERATION_TIMEOUT_SECONDS == 30.0


def test_configured_discovery_timeout_is_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    _config_environment(monkeypatch)
    monkeypatch.setenv("OUTCOME_ACCEPTANCE_DISCOVERY_TIMEOUT_SECONDS", "90")
    assert _config().discovery_timeout_seconds == 90.0


@pytest.mark.parametrize("value", ["invalid", "0", "-1"])
def test_invalid_discovery_timeout_fails_safely(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    _config_environment(monkeypatch)
    monkeypatch.setenv("OUTCOME_ACCEPTANCE_DISCOVERY_TIMEOUT_SECONDS", value)
    with pytest.raises(SystemExit):
        _config()
    error = capsys.readouterr().err
    assert "positive numeric value" in error
    assert "oc_agent_test_secret" not in error


async def test_discovery_timeout_retries_once_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0
    sleeps: list[float] = []

    async def attempt(url: str, api_key: str, timeout: float) -> tuple[set[str], object]:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise DiscoveryAttemptFailure("initialization", "DISCOVERY_TIMEOUT", True)
        assert timeout == 90
        return set(REQUIRED_TOOLS), {"service_name": "Outcome"}

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(outcome_acceptance, "_discovery_attempt", attempt)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    tools, capabilities, retries = await _discover("https://example.test/mcp", "key", 90)
    assert tools == REQUIRED_TOOLS
    assert capabilities == {"service_name": "Outcome"}
    assert retries == 1
    assert attempts == 2
    assert sleeps == [2.0]


async def test_discovery_retries_at_most_once(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = 0

    async def attempt(url: str, api_key: str, timeout: float) -> tuple[set[str], object]:
        nonlocal attempts
        attempts += 1
        raise DiscoveryAttemptFailure("list_tools", "DISCOVERY_CONNECTION_FAILURE", True)

    async def sleep(delay: float) -> None:
        return None

    monkeypatch.setattr(outcome_acceptance, "_discovery_attempt", attempt)
    monkeypatch.setattr(asyncio, "sleep", sleep)
    with pytest.raises(AcceptanceFailure) as captured:
        await _discover("https://example.test/mcp", "key", 30)
    assert attempts == 2
    assert captured.value.stage == "discovery.list_tools"
    assert captured.value.reason == "DISCOVERY_CONNECTION_FAILURE"


async def test_discovery_protocol_failure_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def attempt(url: str, api_key: str, timeout: float) -> tuple[set[str], object]:
        nonlocal attempts
        attempts += 1
        raise DiscoveryAttemptFailure(
            "outcome_capabilities", "DISCOVERY_PROTOCOL_FAILURE", False
        )

    monkeypatch.setattr(outcome_acceptance, "_discovery_attempt", attempt)
    with pytest.raises(AcceptanceFailure) as captured:
        await _discover("https://example.test/mcp", "key", 30)
    assert attempts == 1
    assert captured.value.stage == "discovery.outcome_capabilities"
    assert captured.value.reason == "DISCOVERY_PROTOCOL_FAILURE"


class _AsyncContext:
    async def __aenter__(self) -> _AsyncContext:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _FailingToolClient(_AsyncContext):
    def __init__(self) -> None:
        self.calls = 0

    async def call_tool(self, tool: str, request: object) -> object:
        self.calls += 1
        raise httpx.ReadTimeout("sanitized test timeout")


@pytest.mark.parametrize("tool", ["outcome_authorize", "outcome_execute_authorized"])
async def test_state_changing_transport_failures_are_never_retried(
    monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    client = _FailingToolClient()

    async def session(
        url: str, api_key: str | None, *, timeout_seconds: float = 30
    ) -> tuple[_AsyncContext, _FailingToolClient]:
        assert timeout_seconds == OPERATION_TIMEOUT_SECONDS
        return _AsyncContext(), client

    monkeypatch.setattr(outcome_acceptance, "_session", session)
    with pytest.raises(httpx.ReadTimeout):
        await _call("https://example.test/mcp", "oc_agent_test_secret", tool, {})
    assert client.calls == 1


async def test_discovery_failure_report_is_precise_and_contains_no_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "oc_agent_sentinel_never_emit"

    async def discover(url: str, api_key: str, timeout: float) -> tuple[set[str], object, int]:
        raise AcceptanceFailure(
            "discovery.initialization",
            "DISCOVERY_TIMEOUT",
            "Check endpoint availability and cold-start latency",
        )

    monkeypatch.setattr(outcome_acceptance, "_discover", discover)
    args = argparse.Namespace(
        mcp_url="https://example.test/mcp",
        api_key=secret,
        policy_id="policy",
        verification_result_id="verification",
        environment="test",
        report="unused.json",
        discovery_timeout_seconds=30.0,
    )
    report = await run(args)
    encoded = json.dumps(report)
    assert report["failed_stage"] == "discovery.initialization"
    assert report["reason_codes"] == ["DISCOVERY_TIMEOUT"]
    assert secret not in encoded


async def test_capability_incompatibility_is_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = 0

    async def discover(url: str, api_key: str, timeout: float) -> tuple[set[str], object, int]:
        nonlocal attempts
        attempts += 1
        return (
            set(REQUIRED_TOOLS),
            {
                "supported_tools": sorted(REQUIRED_TOOLS),
                "service_name": "Outcome",
                "mcp_adapter_version": "outcome-mcp-v2",
            },
            0,
        )

    monkeypatch.setattr(outcome_acceptance, "_discover", discover)
    args = argparse.Namespace(
        mcp_url="https://example.test/mcp",
        api_key="oc_agent_test_secret",
        policy_id="policy",
        verification_result_id="verification",
        environment="test",
        report="unused.json",
        discovery_timeout_seconds=30.0,
    )
    report = await run(args)
    assert attempts == 1
    assert report["failed_stage"] == "compatibility"
    assert report["reason_codes"] == ["INCOMPATIBLE_MCP_MAJOR"]
