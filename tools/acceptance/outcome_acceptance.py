from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

REPORT_VERSION = "outcome.controlled-beta-acceptance.v1"
REQUIRED_TOOLS = {
    "outcome_verify",
    "outcome_authorize",
    "outcome_capabilities",
    "outcome_execute_authorized",
}
DECISIONS = {"ALLOW", "RETRY_HIGHER_ASSURANCE", "ESCALATE", "BLOCK"}
ACTION_SCHEMA_VERSION = "action.material.v1"
RECEIPT_VERSION = "outcome.authorization.receipt.v1"


class AcceptanceFailure(RuntimeError):
    def __init__(self, stage: str, reason: str, hint: str) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.hint = hint


def _config() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Outcome black-box controlled-beta acceptance")
    parser.add_argument("--mcp-url", default=os.getenv("OUTCOME_MCP_URL"))
    parser.add_argument("--api-key", default=os.getenv("OUTCOME_API_KEY"))
    parser.add_argument("--policy-id", default=os.getenv("OUTCOME_ACCEPTANCE_POLICY_ID"))
    parser.add_argument(
        "--verification-result-id",
        default=os.getenv("OUTCOME_ACCEPTANCE_VERIFICATION_RESULT_ID"),
    )
    parser.add_argument("--environment", default=os.getenv("OUTCOME_ACCEPTANCE_ENV", "remote"))
    parser.add_argument(
        "--report",
        default=os.getenv("OUTCOME_ACCEPTANCE_REPORT", "artifacts/acceptance-report.json"),
    )
    args = parser.parse_args()
    missing = [
        name
        for name, value in (
            ("OUTCOME_MCP_URL", args.mcp_url),
            ("OUTCOME_API_KEY", args.api_key),
            ("OUTCOME_ACCEPTANCE_POLICY_ID", args.policy_id),
            ("OUTCOME_ACCEPTANCE_VERIFICATION_RESULT_ID", args.verification_result_id),
        )
        if not value
    ]
    if missing:
        parser.error("missing required configuration: " + ", ".join(missing))
    if not str(args.api_key).startswith("oc_agent_"):
        parser.error("OUTCOME_API_KEY must be a normal oc_agent_* credential")
    return args


def _action() -> dict[str, Any]:
    return {
        "action_type": "controlled_beta_test",
        "capability": "authorize",
        "amount_micro_usd": 0,
        "currency": "USD",
        "destination": "synthetic-resource",
        "operation": "record-test-marker",
        "resource": "synthetic-resource",
    }


def _authorization_request(args: argparse.Namespace, key: str) -> dict[str, Any]:
    return {
        "idempotency_key": key,
        "policy_id": args.policy_id,
        "policy_version": 1,
        "requested_assurance": "STANDARD",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(minutes=4)).isoformat(),
        "verification_required": True,
        "verification_result_id": args.verification_result_id,
        "action": {
            "action_schema_version": ACTION_SCHEMA_VERSION,
            "name": "controlled-beta-acceptance",
            "target": "synthetic-resource",
            "material": _action(),
            "ephemeral": {"acceptance_run_id": key},
        },
    }


async def _session(url: str, api_key: str | None):
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    http_client = httpx.AsyncClient(headers=headers, timeout=30)
    transport = streamable_http_client(url, http_client=http_client)
    return http_client, Client(transport)


async def _call(
    url: str, api_key: str | None, tool: str, request: dict[str, Any]
) -> dict[str, Any]:
    http_client, client = await _session(url, api_key)
    async with http_client:
        async with client:
            result = await client.call_tool(tool, {"request": request})
            value = result.structured_content
            if not isinstance(value, dict):
                raise AcceptanceFailure(
                    tool, "MALFORMED_TOOL_RESPONSE", "Inspect MCP adapter output"
                )
            return value


def _assert(condition: bool, stage: str, reason: str, hint: str) -> None:
    if not condition:
        raise AcceptanceFailure(stage, reason, hint)


async def run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.monotonic()
    run_id = f"acceptance-{uuid4()}"
    timings: dict[str, int] = {}
    report: dict[str, Any] = {
        "acceptance_schema_version": REPORT_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "environment_label": args.environment,
        "overall_status": "FAIL",
        "stages": {},
        "reason_codes": [],
    }
    try:
        stage_time = time.monotonic()
        http_client, client = await _session(args.mcp_url, args.api_key)
        async with http_client:
            async with client:
                listed = await client.list_tools()
                tool_names = {tool.name for tool in listed.tools}
                _assert(
                    REQUIRED_TOOLS <= tool_names,
                    "discovery",
                    "REQUIRED_TOOL_MISSING",
                    "Deploy a compatible Outcome MCP adapter",
                )
                capability_result = await client.call_tool("outcome_capabilities", {})
                capabilities = capability_result.structured_content
        _assert(
            isinstance(capabilities, dict),
            "discovery",
            "CAPABILITIES_MALFORMED",
            "Inspect capability response",
        )
        advertised = set(capabilities.get("supported_tools", []))
        _assert(
            advertised <= tool_names,
            "discovery",
            "ADVERTISED_TOOL_UNAVAILABLE",
            "Align discovery metadata with registered tools",
        )
        _assert(
            capabilities.get("service_name") == "Outcome",
            "compatibility",
            "SERVICE_IDENTITY_MISMATCH",
            "Use an Outcome endpoint",
        )
        adapter_version = str(capabilities.get("mcp_adapter_version", ""))
        _assert(
            adapter_version == "outcome-mcp-v1",
            "compatibility",
            "INCOMPATIBLE_MCP_MAJOR",
            "Use outcome-mcp-v1",
        )
        _assert(
            capabilities.get("action_schema_version") == ACTION_SCHEMA_VERSION,
            "compatibility",
            "INCOMPATIBLE_ACTION_SCHEMA",
            "Provision action.material.v1",
        )
        _assert(
            set(capabilities.get("policy_decisions", [])) == DECISIONS,
            "compatibility",
            "POLICY_DECISIONS_INCOMPATIBLE",
            "Deploy the v1 PolicyDecision contract",
        )
        _assert(
            capabilities.get("receipt_support") is True,
            "compatibility",
            "RECEIPTS_UNSUPPORTED",
            "Enable authorization receipts",
        )
        _assert(
            capabilities.get("authentication") == "Authorization: Bearer oc_agent_*",
            "compatibility",
            "AUTH_CONTRACT_INCOMPATIBLE",
            "Use normal agent-key authentication",
        )
        timings["discovery_ms"] = int((time.monotonic() - stage_time) * 1000)
        report["service_version"] = capabilities.get("service_version")
        report["mcp_tool_version"] = adapter_version
        report["capability_versions"] = {
            "action_schema": capabilities.get("action_schema_version"),
            "receipt": capabilities.get("receipt_version"),
        }
        report["discovered_tools"] = sorted(tool_names)

        auth_request = _authorization_request(args, run_id)
        missing = await _call(args.mcp_url, None, "outcome_authorize", auth_request)
        invalid = await _call(
            args.mcp_url, "oc_agent_invalid_invalid", "outcome_authorize", auth_request
        )
        _assert(
            missing.get("error_code") == "AUTHENTICATION_FAILED",
            "authentication",
            "MISSING_AUTH_ACCEPTED",
            "Check MCP authentication middleware",
        )
        _assert(
            invalid.get("error_code") == "AUTHENTICATION_FAILED",
            "authentication",
            "INVALID_AUTH_ACCEPTED",
            "Check agent-key verification",
        )
        report["stages"]["authentication"] = {
            "valid": True,
            "missing_rejected": True,
            "invalid_rejected": True,
        }

        stage_time = time.monotonic()
        response = await _call(args.mcp_url, args.api_key, "outcome_authorize", auth_request)
        _assert(
            response.get("ok") is True,
            "authorization",
            str(response.get("error_code") or "AUTHORIZATION_FAILED"),
            "Check policy, verification fixture, scope, and prepaid funds",
        )
        data = response.get("data") or {}
        decision = data.get("decision")
        _assert(
            decision in DECISIONS,
            "authorization",
            "INVALID_POLICY_DECISION",
            "Inspect public authorization schema",
        )
        _assert(
            decision == "ALLOW",
            "authorization",
            str((data.get("reason_codes") or ["NOT_ALLOWED"])[0]),
            "Check the narrow acceptance policy and VERIFIED fixture",
        )
        receipt = data.get("signed_receipt")
        _assert(
            isinstance(receipt, dict),
            "receipt",
            "ALLOW_WITHOUT_RECEIPT",
            "Inspect receipt issuance configuration",
        )
        payload = receipt.get("payload") or {}
        for field in (
            "receipt_id",
            "account_id",
            "authorization_request_id",
            "action_hash",
            "policy_version",
            "expires_at",
            "signing_key_id",
        ):
            _assert(
                bool(payload.get(field)),
                "receipt",
                f"RECEIPT_{field.upper()}_MISSING",
                "Inspect public receipt contract",
            )
        _assert(
            payload.get("receipt_version") == RECEIPT_VERSION,
            "receipt",
            "RECEIPT_VERSION_INCOMPATIBLE",
            "Deploy the v1 receipt contract",
        )
        _assert(
            payload.get("action_schema_version") == ACTION_SCHEMA_VERSION,
            "receipt",
            "RECEIPT_SCHEMA_MISMATCH",
            "Inspect action binding",
        )
        _assert(
            payload.get("policy_version") == "1",
            "receipt",
            "RECEIPT_POLICY_MISMATCH",
            "Inspect policy binding",
        )
        timings["authorization_ms"] = int((time.monotonic() - stage_time) * 1000)

        retry = await _call(args.mcp_url, args.api_key, "outcome_authorize", auth_request)
        retry_data = retry.get("data") or {}
        _assert(
            retry_data.get("idempotent_replay") is True,
            "idempotency_retry",
            "NOT_IDEMPOTENT_REPLAY",
            "Inspect authorization idempotency",
        )
        for field in (
            "authorization_request_id",
            "authorization_result_id",
            "receipt_id",
            "billing",
        ):
            _assert(
                retry_data.get(field) == data.get(field),
                "idempotency_retry",
                "REPLAY_RESULT_CHANGED",
                "Inspect replay persistence",
            )

        conflict_request = json.loads(json.dumps(auth_request))
        conflict_request["action"]["material"]["resource"] = "changed-resource"
        conflict = await _call(args.mcp_url, args.api_key, "outcome_authorize", conflict_request)
        _assert(
            conflict.get("error_code") == "IDEMPOTENCY_CONFLICT",
            "idempotency_conflict",
            "CONFLICT_NOT_REJECTED",
            "Inspect request fingerprint binding",
        )

        changed_action = dict(_action())
        changed_action["resource"] = "changed-resource"
        changed = await _call(
            args.mcp_url,
            args.api_key,
            "outcome_execute_authorized",
            {
                "execution_request_id": str(uuid4()),
                "signed_receipt": receipt,
                "action_schema_version": ACTION_SCHEMA_VERSION,
                "material_action": changed_action,
            },
        )
        _assert(
            changed.get("ok") is False
            and (changed.get("data") or {}).get("validation_status") == "ACTION_MISMATCH",
            "execution_binding",
            "CHANGED_ACTION_ACCEPTED",
            "Inspect receipt action binding",
        )

        execution_id = str(uuid4())
        exact = await _call(
            args.mcp_url,
            args.api_key,
            "outcome_execute_authorized",
            {
                "execution_request_id": execution_id,
                "signed_receipt": receipt,
                "action_schema_version": ACTION_SCHEMA_VERSION,
                "material_action": _action(),
            },
        )
        _assert(
            exact.get("ok") is True and (exact.get("data") or {}).get("status") == "CONSUMED",
            "execution",
            "EXACT_ACTION_NOT_CONSUMED",
            "Inspect execution validation and consumption",
        )
        replay = await _call(
            args.mcp_url,
            args.api_key,
            "outcome_execute_authorized",
            {
                "execution_request_id": str(uuid4()),
                "signed_receipt": receipt,
                "action_schema_version": ACTION_SCHEMA_VERSION,
                "material_action": _action(),
            },
        )
        _assert(
            replay.get("ok") is False
            and (replay.get("data") or {}).get("status") == "ALREADY_CONSUMED",
            "receipt_replay",
            "CONSUMED_RECEIPT_REUSED",
            "Inspect one-time receipt constraint",
        )

        billing = data.get("billing") or {}
        reserve = billing.get("max_reserved_spend_micro_usd")
        charge = billing.get("actual_charge_micro_usd")
        _assert(
            isinstance(reserve, int) and isinstance(charge, int) and charge <= reserve,
            "billing",
            "BILLING_INVARIANT_FAILED",
            "Inspect quote, reserve, and settlement",
        )
        _assert(
            billing.get("billing_state") == "RELEASED"
            and billing.get("settlement_ledger_transaction_id"),
            "billing",
            "SETTLEMENT_MISSING",
            "Inspect prepaid ledger settlement",
        )

        report.update(
            {
                "authorization_request_id": data.get("authorization_request_id"),
                "authorization_result_id": data.get("authorization_result_id"),
                "policy_decision": decision,
                "evidence_score_basis_points": data.get("evidence_score_basis_points"),
                "billing": billing,
                "receipt": {
                    "receipt_id": data.get("receipt_id"),
                    "key_id": payload.get("signing_key_id"),
                    "structural_validation": "PASS",
                    "cryptographic_validation": "SERVER_EXECUTION_BOUNDARY_PASS",
                },
                "execution_validation": (exact.get("data") or {}).get("status"),
                "receipt_replay": (replay.get("data") or {}).get("status"),
                "idempotency_retry": "PASS",
                "idempotency_conflict": "PASS",
                "overall_status": "PASS",
            }
        )
    except AcceptanceFailure as exc:
        report["failed_stage"] = exc.stage
        report["reason_codes"] = [exc.reason]
        report["remediation_hint"] = exc.hint
    except Exception as exc:
        report["failed_stage"] = "transport"
        report["reason_codes"] = ["SANITIZED_CLIENT_FAILURE"]
        report["remediation_hint"] = (
            f"Check endpoint availability and configuration ({type(exc).__name__})"
        )
    report["durations_ms"] = timings | {"total": int((time.monotonic() - started) * 1000)}
    return report


def main() -> None:
    args = _config()
    report = asyncio.run(run(args))
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if args.api_key in serialized:
        print("acceptance failed: SECRET_SENTINEL_LEAK", file=sys.stderr)
        raise SystemExit(2)
    path = Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized + "\n", encoding="utf-8")
    print(json.dumps({"overall_status": report["overall_status"], "report": str(path)}))
    raise SystemExit(0 if report["overall_status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
