from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from outcome.actions import canonical_material_json
from outcome.auth import ApiKeyScope
from outcome.db.models import (
    Account,
    AgentCredential,
    CreditLedgerEntry,
    CreditLedgerTransaction,
    Policy,
    VerificationRequest,
    VerificationResult,
)
from outcome.domain import AssuranceLevel, PolicyDecision
from outcome.ledger import LedgerAccount, LedgerDirection, LedgerService
from outcome.policies import (
    PolicyEvaluationRequest,
    PolicyEvaluationService,
    verification_reference_from_model,
)
from scripts import acceptance_operator
from scripts.independent_agent_operator import (
    ACCOUNT_ID,
    AGENT_ID,
    FUNDING_AMOUNT_MICRO_USD,
    FUNDING_IDEMPOTENCY_KEY,
    POLICY_ID,
    SYNTHETIC_MATERIAL_ACTION,
    VERIFICATION_REQUEST_ID,
    VERIFICATION_RESULT_ID,
)

ROOT = Path(__file__).resolve().parents[1]


def run_operator(database_url: str, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "independent_agent_operator.py"),
            "--database-url",
            database_url,
            "--output",
            str(output),
            "--environment",
            "controlled-beta",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_independent_agent_provisioning_is_isolated_minimal_and_fail_closed(
    tmp_path: Path,
) -> None:
    assert ACCOUNT_ID != acceptance_operator.ACCOUNT_ID
    assert AGENT_ID != acceptance_operator.AGENT_ID
    assert POLICY_ID != acceptance_operator.POLICY_ID
    assert VERIFICATION_REQUEST_ID != acceptance_operator.VERIFICATION_REQUEST_ID
    assert VERIFICATION_RESULT_ID != acceptance_operator.VERIFICATION_RESULT_ID
    assert SYNTHETIC_MATERIAL_ACTION == {
        "action_type": "controlled_beta_test",
        "capability": "authorize",
        "amount_micro_usd": 0,
        "currency": "USD",
        "destination": "synthetic-resource",
        "operation": "record-test-marker",
        "resource": "synthetic-resource",
    }
    canonical_material_json(material=SYNTHETIC_MATERIAL_ACTION)

    database = tmp_path / "independent-agent.db"
    database_url = f"sqlite+pysqlite:///{database}"
    output = tmp_path / "independent-agent-credential.json"
    first = run_operator(database_url, output)
    assert first.returncode == 0, first.stderr

    artifact = json.loads(output.read_text(encoding="utf-8"))
    assert set(artifact) == {"api_key", "policy_id", "verification_result_id"}
    assert artifact["policy_id"] == str(POLICY_ID)
    assert artifact["verification_result_id"] == str(VERIFICATION_RESULT_ID)
    plaintext_key = artifact["api_key"]
    assert plaintext_key.startswith("oc_agent_")
    assert plaintext_key not in first.stdout
    assert plaintext_key not in first.stderr
    assert stat.S_IMODE(output.stat().st_mode) == 0o600

    engine = create_engine(database_url)
    with Session(engine) as session:
        assert session.get(Account, ACCOUNT_ID) is not None
        credentials = session.scalars(
            select(AgentCredential).where(AgentCredential.account_id == ACCOUNT_ID)
        ).all()
        assert len(credentials) == 1
        credential = credentials[0]
        assert credential.agent_id == AGENT_ID
        assert credential.scopes == [ApiKeyScope.AUTHORIZE_WRITE.value]
        assert credential.key_hash.startswith("pbkdf2_sha256$")
        assert plaintext_key not in credential.key_hash
        assert credential.key_ciphertext_ref is None

        transactions = session.scalars(
            select(CreditLedgerTransaction).where(
                CreditLedgerTransaction.account_id == ACCOUNT_ID
            )
        ).all()
        assert len(transactions) == 1
        transaction = transactions[0]
        assert transaction.idempotency_key == FUNDING_IDEMPOTENCY_KEY
        assert transaction.amount_micro_usd == FUNDING_AMOUNT_MICRO_USD == 1_000_000
        entries = session.scalars(
            select(CreditLedgerEntry).where(
                CreditLedgerEntry.transaction_id == transaction.transaction_id
            )
        ).all()
        debits = sum(
            entry.amount_micro_usd
            for entry in entries
            if entry.direction == LedgerDirection.DEBIT.value
        )
        credits = sum(
            entry.amount_micro_usd
            for entry in entries
            if entry.direction == LedgerDirection.CREDIT.value
        )
        assert debits == credits == FUNDING_AMOUNT_MICRO_USD
        assert {entry.ledger_account for entry in entries} == {
            LedgerAccount.CASH_FUNDING_CLEARING.value,
            LedgerAccount.CUSTOMER_PREPAID_LIABILITY.value,
        }
        assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000

        policy = session.get(Policy, POLICY_ID)
        assert policy is not None
        assert policy.account_id == ACCOUNT_ID
        assert policy.version == 1
        assert policy.status == "PUBLISHED"
        assert policy.body["action_schema_version"] == "action.material.v1"
        assert len(policy.body["rules"]) == 1
        rule = policy.body["rules"][0]
        assert rule["effect"] == "ALLOW"
        assert rule["action_types"] == ["controlled_beta_test"]
        assert rule["capabilities"] == ["authorize"]
        assert rule["allowed_destinations"] == ["synthetic-resource"]
        assert rule["max_amount_micro_usd"] == 0
        assert rule["required_verification_status"] == "VERIFIED"
        assert rule["minimum_evidence_score"] == 9_000
        assert rule["required_assurance"] == "STANDARD"

        request = session.get(VerificationRequest, VERIFICATION_REQUEST_ID)
        result = session.get(VerificationResult, VERIFICATION_RESULT_ID)
        assert request is not None
        assert request.account_id == ACCOUNT_ID
        assert request.agent_id == AGENT_ID
        assert result is not None
        assert result.account_id == ACCOUNT_ID
        assert result.verification_request_id == VERIFICATION_REQUEST_ID
        assert result.status == "VERIFIED"
        assert result.evidence_score_basis_points == 9_500
        assert result.assurance == "STANDARD"
        decision = PolicyEvaluationService(session).evaluate(
            PolicyEvaluationRequest(
                account_id=ACCOUNT_ID,
                policy_id=POLICY_ID,
                policy_version=1,
                material_action=SYNTHETIC_MATERIAL_ACTION,
                action_schema_version="action.material.v1",
                assurance_level=AssuranceLevel.STANDARD,
                verification=verification_reference_from_model(result),
            ),
            correlation_id=uuid4(),
        )
        assert decision.decision is PolicyDecision.ALLOW

    assert plaintext_key.encode() not in database.read_bytes()

    second_output = tmp_path / "second-credential.json"
    second = run_operator(database_url, second_output)
    assert second.returncode != 0
    assert "state already exists; refusing provisioning" in second.stderr
    assert plaintext_key not in second.stdout
    assert plaintext_key not in second.stderr
    assert not second_output.exists()

    with Session(engine) as session:
        assert len(session.scalars(select(Account)).all()) == 1
        assert len(session.scalars(select(AgentCredential)).all()) == 1
        assert len(session.scalars(select(Policy)).all()) == 1
        assert len(session.scalars(select(VerificationRequest)).all()) == 1
        assert len(session.scalars(select(VerificationResult)).all()) == 1
        assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 1
        assert len(session.scalars(select(CreditLedgerEntry)).all()) == 2
        assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000
