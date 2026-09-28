from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import create_engine, or_, select
from sqlalchemy.orm import Session, sessionmaker

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.audit import AuditService
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.db.metadata import metadata
from outcome.db.models import (
    Account,
    AgentCredential,
    CreditLedgerTransaction,
    Policy,
    VerificationRequest,
    VerificationResult,
)
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationMode, VerificationStatus
from outcome.ledger import LedgerService
from outcome.policies import (
    DeterministicPolicy,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
)

ACCOUNT_ID = UUID("41000000-0000-4000-8000-000000000001")
AGENT_ID = UUID("41000000-0000-4000-8000-000000000002")
POLICY_ID = UUID("41000000-0000-4000-8000-000000000003")
VERIFICATION_REQUEST_ID = UUID("41000000-0000-4000-8000-000000000004")
VERIFICATION_RESULT_ID = UUID("41000000-0000-4000-8000-000000000005")
FUNDING_AMOUNT_MICRO_USD = 1_000_000
FUNDING_IDEMPOTENCY_KEY = "TEST_INDEPENDENT_AGENT:controlled-beta-funding-v1"

SYNTHETIC_MATERIAL_ACTION: dict[str, object] = {
    "action_type": "controlled_beta_test",
    "capability": "authorize",
    "amount_micro_usd": 0,
    "currency": "USD",
    "destination": "synthetic-resource",
    "operation": "record-test-marker",
    "resource": "synthetic-resource",
}


class IndependentAgentStateAlreadyExists(RuntimeError):
    pass


def _assert_unprovisioned(session: Session) -> None:
    checks = (
        session.get(Account, ACCOUNT_ID),
        session.scalar(
            select(AgentCredential.id).where(
                or_(
                    AgentCredential.account_id == ACCOUNT_ID,
                    AgentCredential.agent_id == AGENT_ID,
                )
            )
        ),
        session.scalar(
            select(Policy.id).where(
                or_(Policy.id == POLICY_ID, Policy.account_id == ACCOUNT_ID)
            )
        ),
        session.scalar(
            select(VerificationRequest.id).where(
                or_(
                    VerificationRequest.id == VERIFICATION_REQUEST_ID,
                    VerificationRequest.account_id == ACCOUNT_ID,
                    VerificationRequest.agent_id == AGENT_ID,
                )
            )
        ),
        session.scalar(
            select(VerificationResult.id).where(
                or_(
                    VerificationResult.id == VERIFICATION_RESULT_ID,
                    VerificationResult.account_id == ACCOUNT_ID,
                )
            )
        ),
        session.scalar(
            select(CreditLedgerTransaction.id).where(
                or_(
                    CreditLedgerTransaction.account_id == ACCOUNT_ID,
                    CreditLedgerTransaction.idempotency_key == FUNDING_IDEMPOTENCY_KEY,
                )
            )
        ),
    )
    if any(value is not None for value in checks):
        raise IndependentAgentStateAlreadyExists(
            "independent-agent controlled-beta state already exists; refusing provisioning"
        )


def _write_credential_artifact(path: Path, api_key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(
                {
                    "api_key": api_key,
                    "policy_id": str(POLICY_ID),
                    "verification_result_id": str(VERIFICATION_RESULT_ID),
                },
                output,
            )
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Operator-only independent-agent controlled-beta setup"
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--environment", choices=("local", "controlled-beta"), required=True)
    args = parser.parse_args()
    output = Path(args.output)
    if output.exists():
        parser.error("output credential artifact already exists; refusing to overwrite it")

    engine = create_engine(args.database_url)
    metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    artifact_written = False
    committed = False
    try:
        _assert_unprovisioned(session)
        session.add(
            Account(
                id=ACCOUNT_ID,
                display_name="Independent agent controlled beta",
                status="active",
            )
        )
        session.flush()
        PolicyEvaluationService(session, AuditService(session)).publish(
            DeterministicPolicy(
                policy_id=POLICY_ID,
                account_id=ACCOUNT_ID,
                name="independent-agent-controlled-beta-only",
                version=1,
                enabled=True,
                action_schema_version=ACTION_SCHEMA_VERSION,
                rules=(
                    PolicyRule(
                        rule_id="allow-independent-agent-synthetic-marker",
                        effect=PolicyRuleEffect.ALLOW,
                        action_types=("controlled_beta_test",),
                        capabilities=("authorize",),
                        required_verification_status=VerificationStatus.VERIFIED,
                        minimum_evidence_score=9_000,
                        required_assurance=AssuranceLevel.STANDARD,
                        max_amount_micro_usd=0,
                        allowed_destinations=("synthetic-resource",),
                        inconclusive_decision=PolicyDecision.BLOCK,
                        provider_failure_decision=PolicyDecision.BLOCK,
                    ),
                ),
            )
        )
        session.add(
            VerificationRequest(
                id=VERIFICATION_REQUEST_ID,
                account_id=ACCOUNT_ID,
                request_id=uuid4(),
                agent_id=AGENT_ID,
                mode=VerificationMode.INLINE.value,
                requested_assurance=AssuranceLevel.STANDARD.value,
                claim_hash="independent-agent-fixture-claim",
                subject_hash="synthetic-resource",
            )
        )
        session.add(
            VerificationResult(
                id=VERIFICATION_RESULT_ID,
                account_id=ACCOUNT_ID,
                request_id=uuid4(),
                verification_request_id=VERIFICATION_REQUEST_ID,
                status=VerificationStatus.VERIFIED.value,
                evidence_score_basis_points=9_500,
                evidence_score_version="independent-agent-fixture-v1",
                score_factors={},
                evidence_ids_used=[],
                evidence_ids_excluded=[],
                assurance=AssuranceLevel.STANDARD.value,
                reason_codes=["CONTROLLED_INDEPENDENT_AGENT_FIXTURE"],
            )
        )
        LedgerService(session).fund_account(
            account_id=ACCOUNT_ID,
            amount_micro_usd=FUNDING_AMOUNT_MICRO_USD,
            idempotency_key=FUNDING_IDEMPOTENCY_KEY,
            correlation_id=uuid4(),
        )
        api_key = (
            AgentApiKeyAuthenticator(session)
            .create_development_key(
                account_id=ACCOUNT_ID,
                agent_id=AGENT_ID,
                scopes={ApiKeyScope.AUTHORIZE_WRITE},
            )
            .plaintext_key
        )
        _write_credential_artifact(output, api_key)
        artifact_written = True
        session.commit()
        committed = True
        print(json.dumps({"status": "provisioned", "output": str(output)}))
    except IndependentAgentStateAlreadyExists as exc:
        session.rollback()
        parser.exit(1, f"error: {exc}\n")
    except Exception:
        session.rollback()
        if artifact_written and not committed:
            output.unlink(missing_ok=True)
        raise
    finally:
        session.close()


if __name__ == "__main__":
    main()
