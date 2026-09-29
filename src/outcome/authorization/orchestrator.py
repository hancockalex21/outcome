from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.actions import (
    ACTION_SCHEMA_VERSION,
    ActionBindingContext,
    CanonicalizationError,
    action_hash,
    canonical_material_json,
    material_action_hash,
)
from outcome.audit import AuditEventType, AuditService
from outcome.billing import (
    AuthorizationBillingService,
    BillingError,
    BillingQuote,
    BillingResult,
    CrossTenantBillingAccess,
)
from outcome.db.models import AuthorizationRequest, AuthorizationResult, VerificationResult
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationStatus
from outcome.execution import ExecutionAuthorizationRequest, ExecutionAuthorizationValidator
from outcome.policies import (
    PolicyEvaluationRequest,
    PolicyEvaluationService,
    PolicyVerificationReference,
    verification_reference_from_model,
)
from outcome.pricing import BillingMode, CapabilityName
from outcome.receipts import (
    ReceiptService,
    ReceiptVerificationStatus,
    SignedReceipt,
)
from outcome.verification import (
    ProviderPlan,
    VerificationOrchestrationResult,
    VerificationOrchestrator,
    VerificationRequestEnvelope,
    verification_request_fingerprint,
)

AUTHORIZATION_REQUEST_SCHEMA_VERSION = "authorization.request.v1"
AUTHORIZATION_ORCHESTRATION_VERSION = "authorization-orchestration-v1"
DEFAULT_MAX_AUTHORIZATION_TTL_SECONDS = 300


class AuthorizationLifecyclePhase(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    ACTION_BINDING = "ACTION_BINDING"
    VERIFICATION = "VERIFICATION"
    POLICY_EVALUATION = "POLICY_EVALUATION"
    DECISION = "DECISION"
    RECEIPT_ISSUANCE = "RECEIPT_ISSUANCE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AuthorizationOrchestrationReason(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    VERIFICATION_REQUIRED = "VERIFICATION_REQUIRED"
    VERIFICATION_INCONCLUSIVE = "VERIFICATION_INCONCLUSIVE"
    VERIFICATION_CONTRADICTED = "VERIFICATION_CONTRADICTED"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    HIGHER_ASSURANCE_REQUIRED = "HIGHER_ASSURANCE_REQUIRED"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"
    ACTION_BINDING_MISMATCH = "ACTION_BINDING_MISMATCH"
    INVALID_EXPIRATION = "INVALID_EXPIRATION"
    RECEIPT_SIGNING_FAILED = "RECEIPT_SIGNING_FAILED"
    RECEIPT_VERIFICATION_FAILED = "RECEIPT_VERIFICATION_FAILED"
    ALLOWED = "ALLOWED"


class AuthorizationOrchestrationError(ValueError):
    pass


class AuthorizationIdempotencyConflict(AuthorizationOrchestrationError):
    pass


class CrossTenantAuthorizationAccess(PermissionError):
    pass


@dataclass(frozen=True)
class AuthenticatedAuthorizationContext:
    account_id: UUID
    agent_id: UUID


@dataclass(frozen=True)
class AuthorizationMaterial:
    policy_id: UUID
    policy_version: int
    material_action: Mapping[str, object]
    action_schema_version: str
    assurance_level: AssuranceLevel
    authorization_expires_at: datetime
    verification_required: bool = False
    verification_result_id: UUID | None = None
    verification_request: VerificationRequestEnvelope | None = None
    request_config_version: str = AUTHORIZATION_ORCHESTRATION_VERSION


@dataclass(frozen=True)
class AuthorizationRequestEnvelope:
    authenticated: AuthenticatedAuthorizationContext
    material: AuthorizationMaterial
    idempotency_key: str
    correlation_id: UUID
    ephemeral: Mapping[str, object] | None = None


@dataclass(frozen=True)
class AuthorizationOrchestrationResult:
    authorization_request_id: UUID
    authorization_result_id: UUID | None
    account_id: UUID
    decision: PolicyDecision
    lifecycle_state: AuthorizationLifecyclePhase
    action_hash: str | None
    material_hash: str
    policy_id: UUID
    policy_version: int
    policy_hash: str | None
    verification_result_id: UUID | None
    verification_request_id: UUID | None
    verification_status: VerificationStatus | None
    evidence_score_basis_points: int | None
    evidence_score_version: str | None
    assurance_level: AssuranceLevel
    required_assurance: AssuranceLevel | None
    receipt_id: UUID | None
    signed_receipt: SignedReceipt | None
    expires_at: datetime
    request_fingerprint: str
    idempotent_replay: bool
    reason_codes: tuple[str, ...]
    provenance: dict[str, object]


class AuthorizationOrchestrator:
    def __init__(
        self,
        session: Session,
        *,
        policy_service: PolicyEvaluationService | None = None,
        verification_orchestrator: VerificationOrchestrator | None = None,
        receipt_service: ReceiptService,
        execution_validator: ExecutionAuthorizationValidator,
        billing_service: AuthorizationBillingService | None = None,
        audit_service: AuditService | None = None,
        clock: Callable[[], datetime] | None = None,
        max_authorization_ttl: timedelta = timedelta(seconds=DEFAULT_MAX_AUTHORIZATION_TTL_SECONDS),
    ) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)
        self.policy_service = policy_service or PolicyEvaluationService(
            session,
            self.audit_service,
            clock=clock,
        )
        self.verification_orchestrator = verification_orchestrator or VerificationOrchestrator(
            session,
            audit_service=self.audit_service,
            clock=clock,
        )
        self.receipt_service = receipt_service
        self.execution_validator = execution_validator
        self.billing_service = billing_service
        self.clock = clock or (lambda: datetime.now(UTC))
        self.max_authorization_ttl = max_authorization_ttl

    def authorize(
        self,
        request: AuthorizationRequestEnvelope,
        *,
        verification_providers: tuple[ProviderPlan, ...] = (),
    ) -> AuthorizationOrchestrationResult:
        return asyncio.run(
            self.authorize_async(
                request,
                verification_providers=verification_providers,
            )
        )

    async def authorize_async(
        self,
        request: AuthorizationRequestEnvelope,
        *,
        verification_providers: tuple[ProviderPlan, ...] = (),
    ) -> AuthorizationOrchestrationResult:
        issued_at = _aware_utc(self.clock())
        expires_at = self._validate_expiration(request.material.authorization_expires_at, issued_at)
        material_hash = self._material_hash(request.material)
        fingerprint = authorization_request_fingerprint(request.material)
        stored, replay = self._create_or_replay_request(
            request,
            fingerprint,
            material_hash,
            expires_at,
        )
        if replay or stored.lifecycle_state == AuthorizationLifecyclePhase.COMPLETED.value:
            return self._replay_result(stored, fingerprint, request.correlation_id)
        if stored.account_id != request.authenticated.account_id:
            self._fail(
                stored,
                request.correlation_id,
                [AuthorizationOrchestrationReason.SYSTEM_FAILURE.value],
            )
            raise CrossTenantAuthorizationAccess(
                "authorization request belongs to a different account"
            )

        try:
            self._transition(
                stored,
                AuthorizationLifecyclePhase.VALIDATING,
                request.correlation_id,
                [AuthorizationLifecyclePhase.VALIDATING.value],
            )
            billing_quote = self._reserve_billing_if_configured(
                request=request,
                stored=stored,
            )
            verification = await self._verification_reference_async(
                request,
                stored,
                verification_providers,
            )
            self._transition(
                stored,
                AuthorizationLifecyclePhase.POLICY_EVALUATION,
                request.correlation_id,
                [AuthorizationLifecyclePhase.POLICY_EVALUATION.value],
            )
            policy_result = self.policy_service.evaluate(
                PolicyEvaluationRequest(
                    account_id=request.authenticated.account_id,
                    policy_id=request.material.policy_id,
                    policy_version=request.material.policy_version,
                    material_action=request.material.material_action,
                    action_schema_version=request.material.action_schema_version,
                    assurance_level=request.material.assurance_level,
                    verification=verification,
                    evaluated_at=issued_at,
                    ephemeral=request.ephemeral,
                ),
                correlation_id=request.correlation_id,
            )
            self._audit(
                stored,
                AuditEventType.AUTHORIZATION_POLICY_EVALUATED,
                request.correlation_id,
                [reason.value for reason in policy_result.reason_codes],
                policy_hash=policy_result.policy_hash,
                action_hash=policy_result.action_hash,
                decision=policy_result.decision,
            )

            self._transition(
                stored,
                AuthorizationLifecyclePhase.DECISION,
                request.correlation_id,
                [policy_result.decision.value],
            )
            final_action_hash = self._bound_action_hash(stored, request, expires_at)
            if not hmac.compare_digest(material_hash, policy_result.action_hash):
                return self._system_failure_result(
                    stored,
                    request,
                    fingerprint,
                    material_hash,
                    expires_at,
                    [AuthorizationOrchestrationReason.ACTION_BINDING_MISMATCH.value],
                    verification,
                    policy_result.policy_hash,
                    None,
                )

            reason_codes = _authorization_reasons(
                policy_result.decision,
                policy_result.reason_codes,
            )
            if policy_result.decision is not PolicyDecision.ALLOW:
                self._settle_billing_if_configured(
                    request=request,
                    stored=stored,
                    quote=billing_quote,
                    decision=policy_result.decision,
                    system_failure=False,
                    billable_work_occurred=verification is not None,
                )
                return self._persist_result(
                    stored=stored,
                    request=request,
                    fingerprint=fingerprint,
                    material_hash=material_hash,
                    action_hash=final_action_hash,
                    decision=policy_result.decision,
                    reason_codes=reason_codes,
                    verification=verification,
                    policy_hash=policy_result.policy_hash,
                    expires_at=expires_at,
                    signed_receipt=None,
                    complete=True,
                )

            self._transition(
                stored,
                AuthorizationLifecyclePhase.RECEIPT_ISSUANCE,
                request.correlation_id,
                [AuthorizationLifecyclePhase.RECEIPT_ISSUANCE.value],
            )
            self._settle_billing_if_configured(
                request=request,
                stored=stored,
                quote=billing_quote,
                decision=PolicyDecision.ALLOW,
                system_failure=False,
                billable_work_occurred=True,
            )
            signed = self._issue_and_verify_receipt(
                request=request,
                stored=stored,
                action_hash=final_action_hash,
                policy_hash=policy_result.policy_hash,
                verification=verification,
                expires_at=expires_at,
                issued_at=issued_at,
            )
            return self._persist_result(
                stored=stored,
                request=request,
                fingerprint=fingerprint,
                material_hash=material_hash,
                action_hash=final_action_hash,
                decision=PolicyDecision.ALLOW,
                reason_codes=reason_codes,
                verification=verification,
                policy_hash=policy_result.policy_hash,
                expires_at=expires_at,
                signed_receipt=signed,
                complete=True,
            )
        except CrossTenantAuthorizationAccess:
            raise
        except AuthorizationOrchestrationError as exc:
            self._settle_system_failure_billing(request=request, stored=stored)
            return self._system_failure_result(
                stored,
                request,
                fingerprint,
                material_hash,
                expires_at,
                [str(exc) or AuthorizationOrchestrationReason.SYSTEM_FAILURE.value],
                None,
                None,
                exc,
            )
        except Exception as exc:
            self._settle_system_failure_billing(request=request, stored=stored)
            return self._system_failure_result(
                stored,
                request,
                fingerprint,
                material_hash,
                expires_at,
                [AuthorizationOrchestrationReason.SYSTEM_FAILURE.value],
                None,
                None,
                exc,
            )

    def _reserve_billing_if_configured(
        self,
        *,
        request: AuthorizationRequestEnvelope,
        stored: AuthorizationRequest,
    ) -> BillingQuote | None:
        if self.billing_service is None:
            return None
        quote = self.billing_service.quote(
            account_id=request.authenticated.account_id,
            authorization_request_id=stored.id,
            capability=_billing_capability(request.material.material_action),
            execution_mode=_billing_mode(request.material.material_action),
            material={
                "action_schema_version": request.material.action_schema_version,
                "assurance_level": request.material.assurance_level.value,
                "material_action_hash": stored.material_hash,
                "policy_id": str(request.material.policy_id),
                "policy_version": request.material.policy_version,
            },
            correlation_id=request.correlation_id,
        )
        self.billing_service.create_or_reserve(
            account_id=request.authenticated.account_id,
            authorization_request_id=stored.id,
            quote=quote,
            correlation_id=request.correlation_id,
        )
        self.billing_service.mark_in_progress(
            account_id=request.authenticated.account_id,
            authorization_request_id=stored.id,
            correlation_id=request.correlation_id,
        )
        return quote

    def _settle_billing_if_configured(
        self,
        *,
        request: AuthorizationRequestEnvelope,
        stored: AuthorizationRequest,
        quote: BillingQuote | None,
        decision: PolicyDecision,
        system_failure: bool,
        billable_work_occurred: bool,
    ) -> None:
        if self.billing_service is None or quote is None:
            return
        self.billing_service.settle(
            account_id=request.authenticated.account_id,
            authorization_request_id=stored.id,
            quote=quote,
            decision=decision,
            system_failure=system_failure,
            billable_work_occurred=billable_work_occurred,
            correlation_id=request.correlation_id,
        )

    def _settle_system_failure_billing(
        self,
        *,
        request: AuthorizationRequestEnvelope,
        stored: AuthorizationRequest,
    ) -> None:
        if self.billing_service is None:
            return
        try:
            billing = self.billing_service.get_for_authorization(
                account_id=request.authenticated.account_id,
                authorization_request_id=stored.id,
            )
            if billing.actual_charge_micro_usd and billing.actual_charge_micro_usd > 0:
                self.billing_service.compensate_system_failure(
                    account_id=request.authenticated.account_id,
                    authorization_request_id=stored.id,
                    correlation_id=request.correlation_id,
                )
            else:
                self.billing_service.settle(
                    account_id=request.authenticated.account_id,
                    authorization_request_id=stored.id,
                    quote=billing.quote,
                    decision=PolicyDecision.BLOCK,
                    system_failure=True,
                    billable_work_occurred=False,
                    correlation_id=request.correlation_id,
                )
        except (BillingError, CrossTenantBillingAccess):
            return

    def _billing_provenance(self, stored: AuthorizationRequest) -> dict[str, object] | None:
        if self.billing_service is None:
            return None
        try:
            billing = self.billing_service.get_for_authorization(
                account_id=stored.account_id,
                authorization_request_id=stored.id,
            )
        except CrossTenantBillingAccess:
            return None
        return _billing_provenance(billing)

    async def _verification_reference_async(
        self,
        request: AuthorizationRequestEnvelope,
        stored: AuthorizationRequest,
        providers: tuple[ProviderPlan, ...],
    ) -> PolicyVerificationReference | None:
        if request.material.verification_result_id is not None:
            result = self.session.get(VerificationResult, request.material.verification_result_id)
            if result is None or result.account_id != request.authenticated.account_id:
                raise CrossTenantAuthorizationAccess("verification result is unavailable")
            self._audit(
                stored,
                AuditEventType.AUTHORIZATION_VERIFICATION_COMPLETED,
                request.correlation_id,
                [result.status],
                verification_result_id=result.id,
                verification_request_id=result.verification_request_id,
            )
            return verification_reference_from_model(result)
        if not request.material.verification_required:
            return None
        if request.material.verification_request is None:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.VERIFICATION_REQUIRED.value
            )
        self._transition(
            stored,
            AuthorizationLifecyclePhase.VERIFICATION,
            request.correlation_id,
            [AuthorizationLifecyclePhase.VERIFICATION.value],
        )
        verification_result = await self.verification_orchestrator.verify_async(
            request.material.verification_request,
            providers=providers,
        )
        self._audit(
            stored,
            AuditEventType.AUTHORIZATION_VERIFICATION_COMPLETED,
            request.correlation_id,
            [verification_result.status.value],
            verification_result_id=verification_result.verification_result_id,
            verification_request_id=verification_result.verification_request_id,
        )
        return _verification_reference_from_orchestration(verification_result)

    def _issue_and_verify_receipt(
        self,
        *,
        request: AuthorizationRequestEnvelope,
        stored: AuthorizationRequest,
        action_hash: str,
        policy_hash: str,
        verification: PolicyVerificationReference | None,
        expires_at: datetime,
        issued_at: datetime,
    ) -> SignedReceipt:
        try:
            signed = self.receipt_service.issue_authorization_receipt(
                account_id=request.authenticated.account_id,
                authorization_request_id=stored.id,
                authorization_result_id=None,
                action_hash=action_hash,
                action_schema_version=request.material.action_schema_version,
                policy_version=str(request.material.policy_version),
                policy_decision=PolicyDecision.ALLOW,
                verification_status=verification.status if verification else None,
                issued_at=issued_at,
                expires_at=expires_at,
                correlation_id=request.correlation_id,
            )
        except Exception as exc:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.RECEIPT_SIGNING_FAILED.value
            ) from exc
        verification_result = self.receipt_service.verify(
            signed_receipt=signed,
            account_id=request.authenticated.account_id,
            correlation_id=request.correlation_id,
            now=issued_at,
        )
        if verification_result.status is not ReceiptVerificationStatus.SIGNATURE_VALID:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.RECEIPT_VERIFICATION_FAILED.value
            )
        execution_result = self.execution_validator.validate(
            ExecutionAuthorizationRequest(
                signed_receipt=signed,
                proposed_material=request.material.material_action,
                proposed_action_schema_version=request.material.action_schema_version,
                authenticated_account_id=request.authenticated.account_id,
                current_timestamp=issued_at,
            ),
            correlation_id=request.correlation_id,
        )
        if not execution_result.executable:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.RECEIPT_VERIFICATION_FAILED.value
            )
        self._audit(
            stored,
            AuditEventType.AUTHORIZATION_RECEIPT_ISSUED,
            request.correlation_id,
            [PolicyDecision.ALLOW.value],
            policy_hash=policy_hash,
            action_hash=action_hash,
            decision=PolicyDecision.ALLOW,
            receipt_id=signed.payload.receipt_id,
        )
        return signed

    def _persist_result(
        self,
        *,
        stored: AuthorizationRequest,
        request: AuthorizationRequestEnvelope,
        authorization_result_id: UUID | None = None,
        fingerprint: str,
        material_hash: str,
        action_hash: str | None,
        decision: PolicyDecision,
        reason_codes: tuple[str, ...],
        verification: PolicyVerificationReference | None,
        policy_hash: str | None,
        expires_at: datetime,
        signed_receipt: SignedReceipt | None,
        complete: bool,
    ) -> AuthorizationOrchestrationResult:
        existing = self._latest_result(stored)
        if (
            existing is not None
            and stored.lifecycle_state == AuthorizationLifecyclePhase.COMPLETED.value
        ):
            return self._result_from_models(stored, existing, fingerprint, True)

        result = existing or AuthorizationResult(
            id=authorization_result_id or uuid4(),
            account_id=stored.account_id,
            request_id=uuid4(),
            authorization_request_id=stored.id,
            decision=decision.value,
            evidence_score_basis_points=(
                verification.evidence_score_basis_points if verification else None
            ),
            assurance=request.material.assurance_level.value,
            reason_codes=list(reason_codes),
            policy_id=request.material.policy_id,
            policy_version=str(request.material.policy_version),
            policy_hash=policy_hash,
            action_hash=action_hash,
            action_schema_version=request.material.action_schema_version,
            verification_result_id=verification.verification_result_id if verification else None,
            verification_request_id=(
                verification.verification_request_id if verification else None
            ),
            receipt_id=signed_receipt.payload.receipt_id if signed_receipt else None,
            authorization_expires_at=expires_at,
            provenance=_provenance(
                request=request,
                action_hash=action_hash,
                material_hash=material_hash,
                policy_hash=policy_hash,
                verification=verification,
                receipt_id=signed_receipt.payload.receipt_id if signed_receipt else None,
                reason_codes=reason_codes,
                billing=self._billing_provenance(stored),
            ),
        )
        self.session.add(result)
        stored.lifecycle_state = (
            AuthorizationLifecyclePhase.COMPLETED.value
            if complete
            else AuthorizationLifecyclePhase.FAILED.value
        )
        stored.completed_at = _aware_utc(self.clock()) if complete else None
        stored.failed_at = None if complete else _aware_utc(self.clock())
        metadata = dict(stored.lifecycle_metadata)
        metadata.update(
            {
                "authorization_result_id": str(result.id),
                "decision": decision.value,
                "receipt_id": str(signed_receipt.payload.receipt_id) if signed_receipt else None,
                "policy_hash": policy_hash,
                "verification_result_id": (
                    str(verification.verification_result_id) if verification else None
                ),
                "action_hash": action_hash,
            }
        )
        stored.lifecycle_metadata = metadata
        self.session.flush()
        self._audit(
            stored,
            AuditEventType.AUTHORIZATION_DECISION_PRODUCED,
            request.correlation_id,
            list(reason_codes),
            policy_hash=policy_hash,
            action_hash=action_hash,
            decision=decision,
            receipt_id=signed_receipt.payload.receipt_id if signed_receipt else None,
        )
        event_type = (
            AuditEventType.AUTHORIZATION_COMPLETED
            if complete
            else AuditEventType.AUTHORIZATION_FAILED
        )
        self._audit(
            stored,
            event_type,
            request.correlation_id,
            list(reason_codes),
            policy_hash=policy_hash,
            action_hash=action_hash,
            decision=decision,
            receipt_id=signed_receipt.payload.receipt_id if signed_receipt else None,
        )
        return self._result_from_models(stored, result, fingerprint, False, signed_receipt)

    def _system_failure_result(
        self,
        stored: AuthorizationRequest,
        request: AuthorizationRequestEnvelope,
        fingerprint: str,
        material_hash: str,
        expires_at: datetime,
        reason_codes: list[str],
        verification: PolicyVerificationReference | None,
        policy_hash: str | None,
        _exc: Exception | None,
    ) -> AuthorizationOrchestrationResult:
        self._fail(stored, request.correlation_id, reason_codes)
        return self._persist_result(
            stored=stored,
            request=request,
            authorization_result_id=None,
            fingerprint=fingerprint,
            material_hash=material_hash,
            action_hash=None,
            decision=PolicyDecision.BLOCK,
            reason_codes=tuple(reason_codes),
            verification=verification,
            policy_hash=policy_hash,
            expires_at=expires_at,
            signed_receipt=None,
            complete=False,
        )

    def _create_or_replay_request(
        self,
        request: AuthorizationRequestEnvelope,
        fingerprint: str,
        material_hash: str,
        expires_at: datetime,
    ) -> tuple[AuthorizationRequest, bool]:
        existing = self.session.scalar(
            select(AuthorizationRequest).where(
                AuthorizationRequest.account_id == request.authenticated.account_id,
                AuthorizationRequest.idempotency_key == request.idempotency_key,
            )
        )
        if existing is not None:
            self._validate_replay(existing, fingerprint, request.correlation_id)
            return existing, True
        stored = AuthorizationRequest(
            id=uuid4(),
            account_id=request.authenticated.account_id,
            request_id=uuid4(),
            agent_id=request.authenticated.agent_id,
            action_name=_action_name(request.material.material_action),
            action_target_hash=material_hash,
            material_hash=material_hash,
            ephemeral_hash=_hash_ephemeral(request.ephemeral),
            requested_assurance=request.material.assurance_level.value,
            action_schema_version=request.material.action_schema_version,
            policy_id=request.material.policy_id,
            policy_version=str(request.material.policy_version),
            authorization_expires_at=expires_at,
            idempotency_key=request.idempotency_key,
            request_fingerprint=fingerprint,
            lifecycle_state=AuthorizationLifecyclePhase.RECEIVED.value,
            request_config_version=request.material.request_config_version,
            lifecycle_metadata={
                "policy_id": str(request.material.policy_id),
                "policy_version": str(request.material.policy_version),
                "action_schema_version": request.material.action_schema_version,
                "verification_required": request.material.verification_required,
            },
        )
        self.session.add(stored)
        try:
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            replayed = self.session.scalar(
                select(AuthorizationRequest).where(
                    AuthorizationRequest.account_id == request.authenticated.account_id,
                    AuthorizationRequest.idempotency_key == request.idempotency_key,
                )
            )
            if replayed is None:
                raise
            self._validate_replay(replayed, fingerprint, request.correlation_id)
            return replayed, True
        self._audit(
            stored,
            AuditEventType.AUTHORIZATION_RECEIVED,
            request.correlation_id,
            [AuthorizationLifecyclePhase.RECEIVED.value],
            material_hash=material_hash,
        )
        return stored, False

    def _validate_replay(
        self,
        stored: AuthorizationRequest,
        fingerprint: str,
        correlation_id: UUID,
    ) -> None:
        if stored.request_fingerprint != fingerprint:
            self._audit(
                stored,
                AuditEventType.AUTHORIZATION_IDEMPOTENCY_CONFLICT,
                correlation_id,
                [AuthorizationOrchestrationReason.IDEMPOTENCY_CONFLICT.value],
            )
            raise AuthorizationIdempotencyConflict(
                AuthorizationOrchestrationReason.IDEMPOTENCY_CONFLICT.value
            )

    def _replay_result(
        self,
        stored: AuthorizationRequest,
        fingerprint: str,
        correlation_id: UUID,
    ) -> AuthorizationOrchestrationResult:
        result = self._latest_result(stored)
        self._audit(
            stored,
            AuditEventType.AUTHORIZATION_IDEMPOTENT_REPLAY,
            correlation_id,
            [AuthorizationOrchestrationReason.IDEMPOTENT_REPLAY.value],
        )
        if result is None:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.SYSTEM_FAILURE.value
            )
        signed = None
        if result.receipt_id is not None:
            signed = self.receipt_service.get(
                account_id=stored.account_id,
                receipt_id=result.receipt_id,
            )
        return self._result_from_models(stored, result, fingerprint, True, signed)

    def _result_from_models(
        self,
        stored: AuthorizationRequest,
        result: AuthorizationResult,
        fingerprint: str,
        idempotent_replay: bool,
        signed_receipt: SignedReceipt | None = None,
    ) -> AuthorizationOrchestrationResult:
        return AuthorizationOrchestrationResult(
            authorization_request_id=stored.id,
            authorization_result_id=result.id,
            account_id=stored.account_id,
            decision=PolicyDecision(result.decision),
            lifecycle_state=AuthorizationLifecyclePhase(stored.lifecycle_state),
            action_hash=result.action_hash,
            material_hash=stored.material_hash,
            policy_id=result.policy_id or stored.policy_id or UUID(int=0),
            policy_version=int(result.policy_version or stored.policy_version or 0),
            policy_hash=result.policy_hash,
            verification_result_id=result.verification_result_id,
            verification_request_id=result.verification_request_id,
            verification_status=_verification_status_from_provenance(result.provenance),
            evidence_score_basis_points=result.evidence_score_basis_points,
            evidence_score_version=_optional_str(result.provenance.get("evidence_score_version")),
            assurance_level=AssuranceLevel(result.assurance),
            required_assurance=_optional_assurance(result.provenance.get("required_assurance")),
            receipt_id=result.receipt_id,
            signed_receipt=signed_receipt,
            expires_at=result.authorization_expires_at
            or stored.authorization_expires_at
            or _aware_utc(self.clock()),
            request_fingerprint=fingerprint,
            idempotent_replay=idempotent_replay,
            reason_codes=tuple(result.reason_codes),
            provenance=result.provenance,
        )

    def _latest_result(self, stored: AuthorizationRequest) -> AuthorizationResult | None:
        return self.session.scalars(
            select(AuthorizationResult)
            .where(
                AuthorizationResult.account_id == stored.account_id,
                AuthorizationResult.authorization_request_id == stored.id,
            )
            .order_by(AuthorizationResult.created_at.desc(), AuthorizationResult.id.desc())
        ).first()

    def _transition(
        self,
        stored: AuthorizationRequest,
        state: AuthorizationLifecyclePhase,
        correlation_id: UUID,
        reason_codes: list[str],
    ) -> None:
        if stored.lifecycle_state == AuthorizationLifecyclePhase.COMPLETED.value:
            return
        stored.lifecycle_state = state.value
        self.session.flush()
        self._audit(stored, AuditEventType.AUTHORIZATION_VALIDATED, correlation_id, reason_codes)

    def _fail(
        self,
        stored: AuthorizationRequest,
        correlation_id: UUID,
        reason_codes: list[str],
    ) -> None:
        stored.lifecycle_state = AuthorizationLifecyclePhase.FAILED.value
        stored.failed_at = _aware_utc(self.clock())
        self.session.flush()
        self._audit(stored, AuditEventType.AUTHORIZATION_FAILED, correlation_id, reason_codes)

    def _audit(
        self,
        stored: AuthorizationRequest,
        event_type: AuditEventType,
        correlation_id: UUID,
        reason_codes: list[str],
        *,
        material_hash: str | None = None,
        policy_hash: str | None = None,
        action_hash: str | None = None,
        decision: PolicyDecision | None = None,
        verification_result_id: UUID | None = None,
        verification_request_id: UUID | None = None,
        receipt_id: UUID | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "request_id": stored.request_id,
            "request_fingerprint": stored.request_fingerprint,
            "idempotency_key": stored.idempotency_key,
            "lifecycle_state": stored.lifecycle_state,
            "request_config_version": stored.request_config_version,
            "policy_id": stored.policy_id,
            "policy_version": stored.policy_version,
            "reason_codes": reason_codes,
        }
        if material_hash is not None:
            payload["material_hash"] = material_hash
        if policy_hash is not None:
            payload["policy_hash"] = policy_hash
        if action_hash is not None:
            payload["action_hash"] = action_hash
        if decision is not None:
            payload["policy_decision"] = decision
        if verification_result_id is not None:
            payload["verification_result_id"] = verification_result_id
        if verification_request_id is not None:
            payload["verification_request_id"] = verification_request_id
        if receipt_id is not None:
            payload["receipt_id"] = receipt_id
        self.audit_service.append_event(
            account_id=stored.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=stored.id,
            payload=payload,
        )

    def _validate_expiration(self, expires_at: datetime, issued_at: datetime) -> datetime:
        expires = _aware_utc(expires_at)
        if expires <= issued_at:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.INVALID_EXPIRATION.value
            )
        if expires - issued_at > self.max_authorization_ttl:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.INVALID_EXPIRATION.value
            )
        return expires

    def _material_hash(self, material: AuthorizationMaterial) -> str:
        if material.action_schema_version != ACTION_SCHEMA_VERSION:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.INVALID_REQUEST.value
            )
        try:
            return material_action_hash(
                material=material.material_action,
                action_schema_version=material.action_schema_version,
            )
        except CanonicalizationError as exc:
            raise AuthorizationOrchestrationError(
                AuthorizationOrchestrationReason.INVALID_REQUEST.value
            ) from exc

    def _bound_action_hash(
        self,
        stored: AuthorizationRequest,
        request: AuthorizationRequestEnvelope,
        expires_at: datetime,
    ) -> str:
        self._transition(
            stored,
            AuthorizationLifecyclePhase.ACTION_BINDING,
            request.correlation_id,
            [AuthorizationLifecyclePhase.ACTION_BINDING.value],
        )
        return action_hash(
            material=request.material.material_action,
            binding_context=ActionBindingContext(
                account_id=request.authenticated.account_id,
                policy_version=str(request.material.policy_version),
                action_schema_version=request.material.action_schema_version,
                authorization_expires_at=expires_at,
            ),
        )


def authorization_request_fingerprint(material: AuthorizationMaterial) -> str:
    fingerprint_material: dict[str, object] = {
        "action_schema_version": material.action_schema_version,
        "assurance_level": material.assurance_level.value,
        "authorization_expires_at": _aware_utc(material.authorization_expires_at)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "material_action": material.material_action,
        "policy_id": str(material.policy_id),
        "policy_version": material.policy_version,
        "request_config_version": material.request_config_version,
        "verification_required": material.verification_required,
        "verification_result_id": (
            str(material.verification_result_id) if material.verification_result_id else None
        ),
    }
    if material.verification_request is not None:
        fingerprint_material["verification_request_fingerprint"] = verification_request_fingerprint(
            material.verification_request.material
        )
    canonical = canonical_material_json(
        material=fingerprint_material,
        action_schema_version=AUTHORIZATION_REQUEST_SCHEMA_VERSION,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _authorization_reasons(
    decision: PolicyDecision,
    policy_reason_codes: tuple[object, ...],
) -> tuple[str, ...]:
    policy_reasons = tuple(str(getattr(reason, "value", reason)) for reason in policy_reason_codes)
    if decision is PolicyDecision.ALLOW:
        return (AuthorizationOrchestrationReason.ALLOWED.value, *policy_reasons)
    if decision is PolicyDecision.RETRY_HIGHER_ASSURANCE:
        return (
            AuthorizationOrchestrationReason.HIGHER_ASSURANCE_REQUIRED.value,
            *policy_reasons,
        )
    if decision is PolicyDecision.ESCALATE:
        return (AuthorizationOrchestrationReason.ESCALATION_REQUIRED.value, *policy_reasons)
    return (AuthorizationOrchestrationReason.POLICY_BLOCKED.value, *policy_reasons)


def _verification_reference_from_orchestration(
    result: VerificationOrchestrationResult,
) -> PolicyVerificationReference:
    return PolicyVerificationReference(
        verification_result_id=result.verification_result_id or UUID(int=0),
        verification_request_id=result.verification_request_id,
        status=result.status,
        evidence_score_basis_points=(
            result.evidence_score.final_score if result.evidence_score else None
        ),
        evidence_score_version=result.scoring_version,
    )


def _provenance(
    *,
    request: AuthorizationRequestEnvelope,
    action_hash: str | None,
    material_hash: str,
    policy_hash: str | None,
    verification: PolicyVerificationReference | None,
    receipt_id: UUID | None,
    reason_codes: tuple[str, ...],
    billing: Mapping[str, object] | None,
) -> dict[str, object]:
    return {
        "action_binding_version": "action-binding-v1",
        "action_hash": action_hash,
        "action_schema_version": request.material.action_schema_version,
        "assurance_level": request.material.assurance_level.value,
        "billing": dict(billing) if billing is not None else None,
        "evidence_score_basis_points": (
            verification.evidence_score_basis_points if verification else None
        ),
        "evidence_score_version": verification.evidence_score_version if verification else None,
        "material_hash": material_hash,
        "policy_hash": policy_hash,
        "policy_id": str(request.material.policy_id),
        "policy_version": str(request.material.policy_version),
        "reason_codes": list(reason_codes),
        "receipt_id": str(receipt_id) if receipt_id else None,
        "required_assurance": None,
        "verification_request_id": (
            str(verification.verification_request_id) if verification else None
        ),
        "verification_result_id": (
            str(verification.verification_result_id) if verification else None
        ),
        "verification_status": verification.status.value if verification else None,
    }


def _billing_provenance(billing: BillingResult) -> dict[str, object]:
    return {
        "actual_charge_micro_usd": billing.actual_charge_micro_usd,
        "billing_id": str(billing.billing_id),
        "billing_state": billing.state.value,
        "currency": billing.quote.currency,
        "execution_mode": billing.quote.execution_mode.value,
        "max_reserved_spend_micro_usd": billing.quote.max_reserved_spend_micro_usd,
        "pricing_version": billing.quote.pricing_version,
        "quote_fingerprint": billing.quote.quote_fingerprint,
        "reservation_id": str(billing.reservation_id) if billing.reservation_id else None,
        "settlement_ledger_transaction_id": (
            str(billing.settlement_ledger_transaction_id)
            if billing.settlement_ledger_transaction_id
            else None
        ),
    }


def _action_name(material_action: Mapping[str, object]) -> str:
    value = material_action.get("action_type")
    if isinstance(value, str) and value:
        return value[:255]
    return "authorize"


def _hash_ephemeral(ephemeral: Mapping[str, object] | None) -> str:
    if ephemeral is None:
        return hashlib.sha256(b"{}").hexdigest()
    return hashlib.sha256(repr(sorted(ephemeral.items())).encode("utf-8")).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuthorizationOrchestrationError(
            AuthorizationOrchestrationReason.INVALID_EXPIRATION.value
        )
    return value.astimezone(UTC)


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_assurance(value: object) -> AssuranceLevel | None:
    if value is None:
        return None
    return AssuranceLevel(str(value))


def _verification_status_from_provenance(
    provenance: Mapping[str, object],
) -> VerificationStatus | None:
    value = provenance.get("verification_status")
    if value is None:
        return None
    return VerificationStatus(str(value))


def _billing_capability(material_action: Mapping[str, object]) -> CapabilityName:
    value = material_action.get("capability")
    if value == CapabilityName.VERIFY.value:
        return CapabilityName.VERIFY
    return CapabilityName.AUTHORIZE


def _billing_mode(material_action: Mapping[str, object]) -> BillingMode:
    value = material_action.get("billing_mode")
    if value == BillingMode.BYOK.value:
        return BillingMode.BYOK
    return BillingMode.MANAGED


__all__ = [
    "AUTHORIZATION_ORCHESTRATION_VERSION",
    "AUTHORIZATION_REQUEST_SCHEMA_VERSION",
    "AuthenticatedAuthorizationContext",
    "AuthorizationIdempotencyConflict",
    "AuthorizationLifecyclePhase",
    "AuthorizationMaterial",
    "AuthorizationOrchestrationError",
    "AuthorizationOrchestrationReason",
    "AuthorizationOrchestrationResult",
    "AuthorizationOrchestrator",
    "AuthorizationRequestEnvelope",
    "CrossTenantAuthorizationAccess",
    "authorization_request_fingerprint",
]
