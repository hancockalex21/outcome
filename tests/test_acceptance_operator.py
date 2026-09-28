from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from outcome.auth import ApiKeyScope
from outcome.db.models import (
    AgentCredential,
    CreditLedgerEntry,
    CreditLedgerTransaction,
    Policy,
    VerificationResult,
)
from outcome.domain import AssuranceLevel, PolicyDecision
from outcome.ledger import LedgerAccount, LedgerDirection, LedgerService
from outcome.policies import (
    PolicyEvaluationRequest,
    PolicyEvaluationService,
    verification_reference_from_model,
)
from scripts.acceptance_operator import (
    ACCOUNT_ID,
    AGENT_ID,
    FUNDING_AMOUNT_MICRO_USD,
    POLICY_ID,
    VERIFICATION_RESULT_ID,
)

ROOT = Path(__file__).resolve().parents[1]


def run_operator(database_url: str, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "acceptance_operator.py"),
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


def test_controlled_beta_provisioning_is_minimal_and_fails_closed_on_rerun(
    tmp_path: Path,
) -> None:
    database = tmp_path / "operator.db"
    database_url = f"sqlite+pysqlite:///{database}"
    output = tmp_path / "credential.json"

    first = run_operator(database_url, output)
    assert first.returncode == 0, first.stderr
    provisioned = json.loads(output.read_text(encoding="utf-8"))
    plaintext_key = provisioned["api_key"]
    assert plaintext_key.startswith("oc_agent_")

    engine = create_engine(database_url)
    with Session(engine) as session:
        credentials = session.scalars(
            select(AgentCredential).where(
                AgentCredential.account_id == ACCOUNT_ID,
                AgentCredential.agent_id == AGENT_ID,
            )
        ).all()
        assert len(credentials) == 1
        credential = credentials[0]
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
        assert transactions[0].amount_micro_usd == FUNDING_AMOUNT_MICRO_USD == 1_000_000

        entries = session.scalars(
            select(CreditLedgerEntry).where(
                CreditLedgerEntry.transaction_id == transactions[0].transaction_id
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

        policy = session.scalar(select(Policy).where(Policy.account_id == ACCOUNT_ID))
        assert policy is not None
        assert policy.body["rules"][0]["capabilities"] == ["authorize"]
        verification = session.get(VerificationResult, VERIFICATION_RESULT_ID)
        assert verification is not None
        assert verification.status == "VERIFIED"
        assert verification.evidence_score_basis_points == 9_500
        decision = PolicyEvaluationService(session).evaluate(
            PolicyEvaluationRequest(
                account_id=ACCOUNT_ID,
                policy_id=POLICY_ID,
                policy_version=1,
                material_action={
                    "action_type": "controlled_beta_test",
                    "capability": "authorize",
                    "amount_micro_usd": 0,
                    "currency": "USD",
                    "destination": "synthetic-resource",
                    "operation": "record-test-marker",
                    "resource": "synthetic-resource",
                },
                action_schema_version="action.material.v1",
                assurance_level=AssuranceLevel.STANDARD,
                verification=verification_reference_from_model(verification),
            ),
            correlation_id=uuid4(),
        )
        assert decision.decision is PolicyDecision.ALLOW

    assert plaintext_key.encode() not in database.read_bytes()

    second_output = tmp_path / "second-credential.json"
    second = run_operator(database_url, second_output)
    assert second.returncode != 0
    assert "controlled-beta credential has already been provisioned" in second.stderr
    assert plaintext_key not in second.stderr
    assert not second_output.exists()

    with Session(engine) as session:
        assert len(session.scalars(select(AgentCredential)).all()) == 1
        assert len(session.scalars(select(CreditLedgerTransaction)).all()) == 1
        assert LedgerService(session).balance_micro_usd(account_id=ACCOUNT_ID) == 1_000_000
