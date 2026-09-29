from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.audit import AuditEventType, AuditService
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.db.models import Account, BetaRegistration, BetaRegistrationCapacity
from outcome.domain import AssuranceLevel
from outcome.ledger import LedgerService
from outcome.policies import (
    DeterministicPolicy,
    PolicyEvaluationService,
    PolicyRule,
    PolicyRuleEffect,
)

BETA_REGISTRATION_STATUS_COMPLETED = "COMPLETED"
BETA_CAPACITY_ROW_ID = 1
MAX_PROMOTIONAL_CREDIT_MICRO_USD = 10_000_000
STARTER_POLICY_NAME = "Outcome controlled-beta harmless-action starter"
STARTER_ACTION_TYPE = "controlled_beta_test"
STARTER_DESTINATION = "synthetic-resource"


class BetaRegistrationError(RuntimeError):
    pass


class BetaRegistrationConflict(BetaRegistrationError):
    pass


class BetaRegistrationCredentialAlreadyIssued(BetaRegistrationError):
    pass


class BetaRegistrationLimitReached(BetaRegistrationError):
    pass


class BetaRegistrationUnavailable(BetaRegistrationError):
    pass


@dataclass(frozen=True)
class BetaRegistrationInput:
    display_name: str
    idempotency_key: str


@dataclass(frozen=True)
class BetaRegistrationResult:
    registration_id: UUID
    account_id: UUID
    agent_id: UUID
    credential_id: UUID
    plaintext_api_key: str
    scopes: tuple[str, ...]
    policy_id: UUID
    policy_version: int
    promotional_credit_micro_usd: int


class BetaRegistrationService:
    def __init__(
        self,
        session: Session,
        *,
        promotional_credit_micro_usd: int,
        registration_limit: int,
        audit_service: AuditService | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 0 < promotional_credit_micro_usd <= MAX_PROMOTIONAL_CREDIT_MICRO_USD:
            raise ValueError("promotional credit is outside the controlled-beta bound")
        if not 1 <= registration_limit <= 10_000:
            raise ValueError("registration limit is outside the controlled-beta bound")
        self.session = session
        self.promotional_credit_micro_usd = promotional_credit_micro_usd
        self.registration_limit = registration_limit
        self.audit_service = audit_service or AuditService(session)
        self.clock = clock or (lambda: datetime.now(UTC))

    def register(
        self,
        request: BetaRegistrationInput,
        *,
        correlation_id: UUID,
    ) -> BetaRegistrationResult:
        key_hash = _sha256(request.idempotency_key)
        fingerprint = _request_fingerprint(request.display_name)
        existing = self.session.scalar(
            select(BetaRegistration).where(BetaRegistration.idempotency_key_hash == key_hash)
        )
        if existing is not None:
            if existing.request_fingerprint != fingerprint:
                raise BetaRegistrationConflict("idempotency key reused with different input")
            raise BetaRegistrationCredentialAlreadyIssued(
                "registration completed; plaintext credential cannot be replayed"
            )

        capacity = self.session.scalar(
            select(BetaRegistrationCapacity)
            .where(BetaRegistrationCapacity.id == BETA_CAPACITY_ROW_ID)
            .with_for_update()
        )
        if capacity is None:
            raise BetaRegistrationUnavailable("registration capacity state is unavailable")
        existing_after_lock = self.session.scalar(
            select(BetaRegistration).where(BetaRegistration.idempotency_key_hash == key_hash)
        )
        if existing_after_lock is not None:
            if existing_after_lock.request_fingerprint != fingerprint:
                raise BetaRegistrationConflict("idempotency key reused with different input")
            raise BetaRegistrationCredentialAlreadyIssued(
                "registration completed; plaintext credential cannot be replayed"
            )
        if capacity.registrations_used >= self.registration_limit:
            raise BetaRegistrationLimitReached("controlled-beta registration limit reached")

        registration_id = uuid4()
        account_id = uuid4()
        agent_id = uuid4()
        policy_id = uuid4()
        account = Account(id=account_id, display_name=request.display_name, status="active")
        self.session.add(account)
        self.session.flush()

        key_result = AgentApiKeyAuthenticator(self.session).create_key(
            account_id=account_id,
            agent_id=agent_id,
            scopes={ApiKeyScope.AUTHORIZE_WRITE},
        )
        key_result.credential.metadata_json = {
            "provisioning_source": "controlled_beta_registration",
            "registration_id": str(registration_id),
        }
        policy = PolicyEvaluationService(
            self.session,
            self.audit_service,
            clock=self.clock,
        ).publish(_starter_policy(account_id=account_id, policy_id=policy_id, now=self.clock()))
        funding = LedgerService(self.session, self.audit_service).grant_promotional_credit(
            account_id=account_id,
            amount_micro_usd=self.promotional_credit_micro_usd,
            idempotency_key=f"beta-promotion:{registration_id}",
            correlation_id=correlation_id,
        )
        registration = BetaRegistration(
            id=registration_id,
            account_id=account_id,
            idempotency_key_hash=key_hash,
            request_fingerprint=fingerprint,
            agent_id=agent_id,
            credential_id=key_result.credential.id,
            policy_id=policy.id,
            promotional_ledger_transaction_id=funding.transaction_id,
            promotional_credit_micro_usd=self.promotional_credit_micro_usd,
            status=BETA_REGISTRATION_STATUS_COMPLETED,
        )
        self.session.add(registration)
        capacity.registrations_used += 1
        self.session.flush()
        self._audit_registration(registration, policy.version, correlation_id)
        return BetaRegistrationResult(
            registration_id=registration_id,
            account_id=account_id,
            agent_id=agent_id,
            credential_id=key_result.credential.id,
            plaintext_api_key=key_result.plaintext_key,
            scopes=(ApiKeyScope.AUTHORIZE_WRITE.value,),
            policy_id=policy.id,
            policy_version=policy.version,
            promotional_credit_micro_usd=self.promotional_credit_micro_usd,
        )

    def _audit_registration(
        self,
        registration: BetaRegistration,
        policy_version: int,
        correlation_id: UUID,
    ) -> None:
        common = {
            "registration_id": registration.id,
            "agent_credential_id": registration.credential_id,
            "policy_id": registration.policy_id,
            "policy_version": policy_version,
            "promotional_credit_micro_usd": registration.promotional_credit_micro_usd,
            "credential_scopes": [ApiKeyScope.AUTHORIZE_WRITE.value],
        }
        for event_type in (
            AuditEventType.BETA_CREDENTIAL_CREATED,
            AuditEventType.BETA_STARTER_POLICY_CREATED,
            AuditEventType.BETA_REGISTRATION_COMPLETED,
        ):
            self.audit_service.append_event(
                account_id=registration.account_id,
                event_type=event_type,
                correlation_id=correlation_id,
                request_id=registration.id,
                payload=common,
            )


def _starter_policy(*, account_id: UUID, policy_id: UUID, now: datetime) -> DeterministicPolicy:
    return DeterministicPolicy(
        policy_id=policy_id,
        account_id=account_id,
        name=STARTER_POLICY_NAME,
        version=1,
        enabled=True,
        action_schema_version=ACTION_SCHEMA_VERSION,
        rules=(
            PolicyRule(
                rule_id="allow-harmless-controlled-beta-action",
                effect=PolicyRuleEffect.ALLOW,
                action_types=(STARTER_ACTION_TYPE,),
                capabilities=("authorize",),
                required_assurance=AssuranceLevel.STANDARD,
                max_amount_micro_usd=0,
                allowed_destinations=(STARTER_DESTINATION,),
            ),
        ),
        effective_at=now,
    )


def _request_fingerprint(display_name: str) -> str:
    canonical = json.dumps(
        {"display_name": display_name},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _sha256(canonical)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
