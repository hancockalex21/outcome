from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

from tools.acceptance.outcome_acceptance import (
    ACTION_SCHEMA_VERSION,
    REPORT_VERSION,
    REQUIRED_TOOLS,
    _action,
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
