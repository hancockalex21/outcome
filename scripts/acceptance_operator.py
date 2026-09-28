from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.audit import AuditService
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.db.metadata import metadata
from outcome.db.models import Account, AgentCredential, VerificationRequest, VerificationResult
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationMode, VerificationStatus
from outcome.ledger import LedgerService
from outcome.policies import (
    DeterministicPolicy,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
)

ACCOUNT_ID = UUID("32000000-0000-4000-8000-000000000001")
AGENT_ID = UUID("32000000-0000-4000-8000-000000000002")
POLICY_ID = UUID("32000000-0000-4000-8000-000000000003")
VERIFICATION_REQUEST_ID = UUID("32000000-0000-4000-8000-000000000004")
VERIFICATION_RESULT_ID = UUID("32000000-0000-4000-8000-000000000005")
FUNDING_AMOUNT_MICRO_USD = 1_000_000


class ControlledBetaCredentialAlreadyProvisioned(RuntimeError):
    pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Operator-only controlled-beta fixture setup")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--environment", choices=("local", "controlled-beta"), required=True)
    args = parser.parse_args()
    engine = create_engine(args.database_url)
    metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        existing_credential = session.scalar(
            select(AgentCredential.id).where(
                AgentCredential.account_id == ACCOUNT_ID,
                AgentCredential.agent_id == AGENT_ID,
            )
        )
        if existing_credential is not None:
            raise ControlledBetaCredentialAlreadyProvisioned(
                "controlled-beta credential has already been provisioned"
            )
        if session.get(Account, ACCOUNT_ID) is None:
            session.add(
                Account(id=ACCOUNT_ID, display_name="Controlled beta acceptance", status="active")
            )
            session.flush()
        PolicyEvaluationService(session, AuditService(session)).publish(
            DeterministicPolicy(
                policy_id=POLICY_ID,
                account_id=ACCOUNT_ID,
                name="controlled-beta-acceptance-only",
                version=1,
                enabled=True,
                action_schema_version=ACTION_SCHEMA_VERSION,
                rules=(
                    PolicyRule(
                        rule_id="allow-controlled-beta-marker",
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
        if session.get(VerificationRequest, VERIFICATION_REQUEST_ID) is None:
            session.add(
                VerificationRequest(
                    id=VERIFICATION_REQUEST_ID,
                    account_id=ACCOUNT_ID,
                    request_id=uuid4(),
                    agent_id=AGENT_ID,
                    mode=VerificationMode.INLINE.value,
                    requested_assurance=AssuranceLevel.STANDARD.value,
                    claim_hash="acceptance-fixture-claim",
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
                    evidence_score_version="acceptance-fixture-v1",
                    score_factors={},
                    evidence_ids_used=[],
                    evidence_ids_excluded=[],
                    assurance=AssuranceLevel.STANDARD.value,
                    reason_codes=["CONTROLLED_ACCEPTANCE_FIXTURE"],
                )
            )
        LedgerService(session).fund_account(
            account_id=ACCOUNT_ID,
            amount_micro_usd=FUNDING_AMOUNT_MICRO_USD,
            idempotency_key="TEST_ACCEPTANCE:controlled-beta-funding-v1",
            correlation_id=uuid4(),
        )
        key = (
            AgentApiKeyAuthenticator(session)
            .create_development_key(
                account_id=ACCOUNT_ID,
                agent_id=AGENT_ID,
                scopes={ApiKeyScope.AUTHORIZE_WRITE},
            )
            .plaintext_key
        )
        session.commit()
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(
                {
                    "api_key": key,
                    "policy_id": str(POLICY_ID),
                    "verification_result_id": str(VERIFICATION_RESULT_ID),
                    "provisioned_at": datetime.now(UTC).isoformat(),
                }
            ),
            encoding="utf-8",
        )
        output.chmod(0o600)
        print(json.dumps({"status": "provisioned", "output": str(output)}))
    finally:
        session.close()


if __name__ == "__main__":
    main()
