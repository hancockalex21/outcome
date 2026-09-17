from __future__ import annotations

import asyncio
import hashlib
import inspect
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.actions.material import CanonicalizationError, canonical_material_json
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import ProviderAttempt, VerificationRequest, VerificationResult
from outcome.domain import AssuranceLevel, VerificationMode, VerificationStatus
from outcome.evidence import (
    EvidenceLineageInput,
    EvidenceLineageService,
    EvidenceLineageType,
    EvidenceNormalizationError,
    EvidenceNormalizationInput,
    EvidenceNormalizer,
    EvidenceScore,
    EvidenceScoringService,
    EvidenceStance,
    EvidenceStanceInput,
    InertEvidence,
    SourceClass,
)
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderAttemptOutcome,
    ProviderCredentialMode,
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderHealthRequest,
    ProviderHealthService,
    ProviderRightsRequest,
    ProviderRightsService,
)

VERIFICATION_REQUEST_SCHEMA_VERSION = "verification.request.v1"
VERIFICATION_ORCHESTRATION_VERSION = "verification-orchestration-v1"
VERIFICATION_EXECUTION_PLAN_VERSION = "verification-provider-plan-v1"


class VerificationLifecyclePhase(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    PROVIDER_ELIGIBILITY = "PROVIDER_ELIGIBILITY"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    EVIDENCE_NORMALIZATION = "EVIDENCE_NORMALIZATION"
    LINEAGE_ANALYSIS = "LINEAGE_ANALYSIS"
    EVIDENCE_ASSESSMENT = "EVIDENCE_ASSESSMENT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VerificationOrchestrationReason(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    PROVIDER_RIGHTS_UNAVAILABLE = "PROVIDER_RIGHTS_UNAVAILABLE"
    PROVIDER_HEALTH_UNSAFE = "PROVIDER_HEALTH_UNSAFE"
    NO_ELIGIBLE_PROVIDER = "NO_ELIGIBLE_PROVIDER"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    COLLECTION_DEADLINE_REACHED = "COLLECTION_DEADLINE_REACHED"
    CONFIGURATION_UNSAFE = "CONFIGURATION_UNSAFE"


class VerificationOrchestrationError(ValueError):
    pass


class VerificationIdempotencyConflict(VerificationOrchestrationError):
    pass


class CrossTenantVerificationAccess(PermissionError):
    pass


@dataclass(frozen=True)
class AuthenticatedVerificationContext:
    account_id: UUID
    agent_id: UUID


@dataclass(frozen=True)
class VerificationMaterial:
    capability: CapabilityName
    mode: VerificationMode
    assurance: AssuranceLevel
    claim: Mapping[str, object]
    subject: Mapping[str, object]
    provider_ids: tuple[UUID, ...]
    request_config_version: str = VERIFICATION_ORCHESTRATION_VERSION


@dataclass(frozen=True)
class VerificationRequestEnvelope:
    authenticated: AuthenticatedVerificationContext
    material: VerificationMaterial
    idempotency_key: str
    correlation_id: UUID
    ephemeral: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ProviderEvidencePayload:
    source_uri: str | None
    source_class: SourceClass
    content_type: str
    body: bytes | str
    observed_at: datetime
    stance: EvidenceStance
    lineage_type: EvidenceLineageType = EvidenceLineageType.UNKNOWN
    parent_evidence_ids: tuple[UUID, ...] = ()
    origin_reference: str | None = None
    publisher_identity: str | None = None
    canonical_source_identity: str | None = None
    coverage_basis_points: int = 10_000
    authority_metadata: dict[str, object] | None = None
    lineage_metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class ProviderEvidenceResult:
    provider_id: UUID
    provider_alias: str | None
    capability: CapabilityName
    attempt_outcome: ProviderAttemptOutcome
    latency_ms: int | None
    evidence: tuple[ProviderEvidencePayload, ...] = ()


@dataclass(frozen=True)
class EvidenceProviderRequest:
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID
    capability: CapabilityName
    mode: VerificationMode
    assurance: AssuranceLevel


class EvidenceProvider(Protocol):
    def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        raise NotImplementedError


class AsyncEvidenceProvider(Protocol):
    async def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        raise NotImplementedError


@dataclass(frozen=True)
class ProviderPlan:
    provider_id: UUID
    provider_alias: str
    billing_mode: BillingMode
    requested_region: str
    credential_mode: ProviderCredentialMode
    adapter: EvidenceProvider
    requested_data_use: ProviderDataUse = ProviderDataUse.CLAIM_VERIFICATION
    requested_execution_mode: ProviderExecutionMode = ProviderExecutionMode.INLINE
    evidence_retention_requested: bool = False
    caching_requested: bool = False


@dataclass(frozen=True)
class ProviderCollectionConfig:
    max_providers: int = 8
    max_concurrency: int = 4
    per_provider_timeout: timedelta = timedelta(seconds=5)
    overall_deadline: timedelta = timedelta(seconds=15)
    max_attempts_per_provider: int = 1


@dataclass(frozen=True)
class PlannedProviderCollection:
    provider_id: UUID
    provider_alias: str
    capability: CapabilityName
    rights_version: str | None
    planned_order: int
    timeout_ms: int
    execution_mode: ProviderExecutionMode
    billing_mode: BillingMode
    config_version: str = VERIFICATION_EXECUTION_PLAN_VERSION


@dataclass(frozen=True)
class ProviderExecutionPlanItem:
    provider: ProviderPlan
    plan: PlannedProviderCollection


@dataclass(frozen=True)
class ProviderCollectionOutcome:
    plan: PlannedProviderCollection
    attempt_outcome: ProviderAttemptOutcome
    evidence: tuple[ProviderEvidencePayload, ...]
    latency_ms: int | None
    started_at: datetime
    completed_at: datetime
    deadline_exceeded: bool = False
    error_code: str | None = None


@dataclass(frozen=True)
class VerificationOrchestrationResult:
    verification_request_id: UUID
    account_id: UUID
    status: VerificationStatus
    lifecycle_state: VerificationLifecyclePhase
    evidence_score: EvidenceScore | None
    verification_result_id: UUID | None
    request_fingerprint: str
    idempotent_replay: bool
    reason_codes: tuple[str, ...]
    evidence_ids_used: tuple[UUID, ...]
    evidence_ids_excluded: tuple[UUID, ...]
    providers_contributed: tuple[UUID, ...]
    providers_failed: tuple[UUID, ...]
    scoring_version: str | None
    lineage_versions: tuple[str, ...]


class VerificationOrchestrator:
    def __init__(
        self,
        session: Session,
        *,
        audit_service: AuditService | None = None,
        provider_rights_service: ProviderRightsService | None = None,
        provider_health_service: ProviderHealthService | None = None,
        evidence_normalizer: EvidenceNormalizer | None = None,
        lineage_service: EvidenceLineageService | None = None,
        scoring_service: EvidenceScoringService | None = None,
        collection_config: ProviderCollectionConfig | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)
        self.provider_rights_service = provider_rights_service or ProviderRightsService(
            session,
            self.audit_service,
        )
        self.provider_health_service = provider_health_service or ProviderHealthService(
            session,
            self.audit_service,
        )
        self.evidence_normalizer = evidence_normalizer or EvidenceNormalizer(
            session,
            self.audit_service,
        )
        self.lineage_service = lineage_service or EvidenceLineageService(
            session,
            self.audit_service,
        )
        self.scoring_service = scoring_service or EvidenceScoringService(
            session,
            self.audit_service,
            lineage_service=self.lineage_service,
        )
        self.collection_config = collection_config or ProviderCollectionConfig()
        _validate_collection_config(self.collection_config)
        self.clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        request: VerificationRequestEnvelope,
        *,
        providers: tuple[ProviderPlan, ...],
    ) -> VerificationOrchestrationResult:
        return asyncio.run(self.verify_async(request, providers=providers))

    async def verify_async(
        self,
        request: VerificationRequestEnvelope,
        *,
        providers: tuple[ProviderPlan, ...],
    ) -> VerificationOrchestrationResult:
        now = _aware_utc(self.clock())
        try:
            fingerprint = verification_request_fingerprint(request.material)
        except CanonicalizationError as exc:
            raise VerificationOrchestrationError(
                VerificationOrchestrationReason.INVALID_REQUEST.value
            ) from exc
        stored, replay = self._create_or_replay_request(request, fingerprint, now)
        if replay:
            return self._replay_result(stored, fingerprint, request.correlation_id)
        if stored.lifecycle_state == VerificationLifecyclePhase.COMPLETED.value:
            return self._replay_result(stored, fingerprint, request.correlation_id)

        self._transition(
            stored,
            VerificationLifecyclePhase.VALIDATING,
            request.correlation_id,
            [VerificationLifecyclePhase.VALIDATING.value],
        )
        if stored.account_id != request.authenticated.account_id:
            self._fail(
                stored,
                request.correlation_id,
                [VerificationOrchestrationReason.SYSTEM_FAILURE.value],
            )
            raise CrossTenantVerificationAccess(
                "verification request belongs to a different account"
            )

        accepted: list[InertEvidence] = []
        stances: list[EvidenceStanceInput] = []
        providers_contributed: list[UUID] = []
        providers_failed: list[UUID] = []
        lineage_versions: set[str] = set()

        plan_items, ineligible = self._build_execution_plan(
            stored=stored,
            request=request,
            providers=providers,
            now=now,
        )
        providers_failed.extend(provider_id for provider_id, _reason in ineligible)
        if plan_items:
            self._transition(
                stored,
                VerificationLifecyclePhase.EVIDENCE_COLLECTION,
                request.correlation_id,
                [VerificationLifecyclePhase.EVIDENCE_COLLECTION.value],
            )
            outcomes = await self._collect_provider_outcomes(
                stored=stored,
                request=request,
                planned=plan_items,
            )
        else:
            outcomes = ()

        for outcome in outcomes:
            self.provider_health_service.record_attempt(
                account_id=request.authenticated.account_id,
                provider_id=outcome.plan.provider_id,
                capability=request.material.capability,
                outcome=outcome.attempt_outcome,
                correlation_id=request.correlation_id,
                latency_ms=outcome.latency_ms,
                occurred_at=outcome.completed_at,
            )
            self._persist_provider_attempt(
                stored=stored,
                outcome=outcome,
                correlation_id=request.correlation_id,
            )
            if outcome.attempt_outcome is ProviderAttemptOutcome.SYSTEM_FAILURE:
                return self._system_failure(stored, fingerprint, request.correlation_id)
            if outcome.attempt_outcome is not ProviderAttemptOutcome.SUCCESS:
                providers_failed.append(outcome.plan.provider_id)
                continue
            provider_plan = _provider_plan_for_outcome(providers, outcome)
            provider_result = ProviderEvidenceResult(
                provider_id=outcome.plan.provider_id,
                provider_alias=outcome.plan.provider_alias,
                capability=outcome.plan.capability,
                attempt_outcome=outcome.attempt_outcome,
                latency_ms=outcome.latency_ms,
                evidence=outcome.evidence,
            )
            provider_accepted = self._normalize_and_lineage(
                stored=stored,
                provider=provider_plan,
                provider_result=provider_result,
                correlation_id=request.correlation_id,
                accepted=accepted,
                stances=stances,
                lineage_versions=lineage_versions,
            )
            if provider_accepted:
                providers_contributed.append(outcome.plan.provider_id)
            elif outcome.evidence:
                providers_failed.append(outcome.plan.provider_id)

        if not providers_contributed and providers_failed:
            return self._provider_failed(
                stored,
                fingerprint,
                request.correlation_id,
                providers_failed,
            )
        if not providers and not accepted:
            return self._provider_failed(
                stored,
                fingerprint,
                request.correlation_id,
                providers_failed,
            )

        self._transition(
            stored,
            VerificationLifecyclePhase.EVIDENCE_ASSESSMENT,
            request.correlation_id,
            [VerificationLifecyclePhase.EVIDENCE_ASSESSMENT.value],
        )
        score = self.scoring_service.score(
            account_id=request.authenticated.account_id,
            verification_request_id=stored.id,
            evidence_ids=tuple(item.evidence_id for item in accepted),
            stances=tuple(stances),
            correlation_id=request.correlation_id,
        )
        result_model = self._latest_result(stored)
        self._complete(
            stored=stored,
            score=score,
            result_model=result_model,
            request_fingerprint=fingerprint,
            correlation_id=request.correlation_id,
            providers_contributed=tuple(providers_contributed),
            providers_failed=tuple(providers_failed),
            lineage_versions=tuple(sorted(lineage_versions)),
        )
        return VerificationOrchestrationResult(
            verification_request_id=stored.id,
            account_id=stored.account_id,
            status=score.verification_status,
            lifecycle_state=VerificationLifecyclePhase.COMPLETED,
            evidence_score=score,
            verification_result_id=result_model.id if result_model is not None else None,
            request_fingerprint=fingerprint,
            idempotent_replay=False,
            reason_codes=score.reason_codes,
            evidence_ids_used=score.evidence_ids_used,
            evidence_ids_excluded=score.evidence_ids_excluded,
            providers_contributed=tuple(providers_contributed),
            providers_failed=tuple(providers_failed),
            scoring_version=score.evidence_score_version,
            lineage_versions=tuple(sorted(lineage_versions)),
        )

    def _build_execution_plan(
        self,
        *,
        stored: VerificationRequest,
        request: VerificationRequestEnvelope,
        providers: tuple[ProviderPlan, ...],
        now: datetime,
    ) -> tuple[tuple[ProviderExecutionPlanItem, ...], tuple[tuple[UUID, str], ...]]:
        if len(providers) > self.collection_config.max_providers:
            providers = providers[: self.collection_config.max_providers]
        planned: list[ProviderExecutionPlanItem] = []
        ineligible: list[tuple[UUID, str]] = []
        ordered = tuple(
            sorted(
                enumerate(providers),
                key=lambda item: (str(item[1].provider_id), item[1].provider_alias),
            )
        )
        for planned_order, (_original_index, provider) in enumerate(ordered):
            self._transition(
                stored,
                VerificationLifecyclePhase.PROVIDER_ELIGIBILITY,
                request.correlation_id,
                [VerificationLifecyclePhase.PROVIDER_ELIGIBILITY.value],
            )
            rights = self.provider_rights_service.authorize(
                ProviderRightsRequest(
                    account_id=request.authenticated.account_id,
                    provider_id=provider.provider_id,
                    provider_alias=provider.provider_alias,
                    capability=request.material.capability,
                    billing_mode=provider.billing_mode,
                    requested_region=provider.requested_region,
                    requested_data_use=provider.requested_data_use,
                    requested_execution_mode=provider.requested_execution_mode,
                    credential_mode=provider.credential_mode,
                    evidence_retention_requested=provider.evidence_retention_requested,
                    caching_requested=provider.caching_requested,
                    evaluated_at=now,
                ),
                correlation_id=request.correlation_id,
            )
            if not rights.allowed:
                ineligible.append(
                    (
                        provider.provider_id,
                        VerificationOrchestrationReason.PROVIDER_RIGHTS_UNAVAILABLE.value,
                    )
                )
                self._audit(
                    stored,
                    AuditEventType.VERIFICATION_PROVIDER_ELIGIBILITY_EVALUATED,
                    request.correlation_id,
                    [VerificationOrchestrationReason.PROVIDER_RIGHTS_UNAVAILABLE.value],
                    provider_id=provider.provider_id,
                )
                continue
            health = self.provider_health_service.evaluate(
                ProviderHealthRequest(
                    account_id=request.authenticated.account_id,
                    provider_id=provider.provider_id,
                    capability=request.material.capability,
                    evaluated_at=now,
                ),
                correlation_id=request.correlation_id,
            )
            if not health.usable:
                ineligible.append(
                    (
                        provider.provider_id,
                        VerificationOrchestrationReason.PROVIDER_HEALTH_UNSAFE.value,
                    )
                )
                self._audit(
                    stored,
                    AuditEventType.VERIFICATION_PROVIDER_ELIGIBILITY_EVALUATED,
                    request.correlation_id,
                    [VerificationOrchestrationReason.PROVIDER_HEALTH_UNSAFE.value],
                    provider_id=provider.provider_id,
                )
                self._persist_skipped_provider_attempt(
                    stored=stored,
                    provider=provider,
                    planned_order=planned_order,
                    reason=health.provider_health.value,
                    correlation_id=request.correlation_id,
                )
                continue
            plan = PlannedProviderCollection(
                provider_id=provider.provider_id,
                provider_alias=provider.provider_alias,
                capability=request.material.capability,
                rights_version=rights.rights_version,
                planned_order=planned_order,
                timeout_ms=_milliseconds(self.collection_config.per_provider_timeout),
                execution_mode=provider.requested_execution_mode,
                billing_mode=provider.billing_mode,
            )
            planned.append(ProviderExecutionPlanItem(provider=provider, plan=plan))
        self._audit(
            stored,
            AuditEventType.VERIFICATION_COLLECTION_PLANNED,
            request.correlation_id,
            [VERIFICATION_EXECUTION_PLAN_VERSION],
            planned_provider_ids=[item.plan.provider_id for item in planned],
        )
        return tuple(planned), tuple(ineligible)

    async def _collect_provider_outcomes(
        self,
        *,
        stored: VerificationRequest,
        request: VerificationRequestEnvelope,
        planned: tuple[ProviderExecutionPlanItem, ...],
    ) -> tuple[ProviderCollectionOutcome, ...]:
        semaphore = asyncio.Semaphore(self.collection_config.max_concurrency)
        deadline_seconds = self.collection_config.overall_deadline.total_seconds()
        tasks = [
            asyncio.create_task(
                self._collect_one_provider(
                    stored=stored,
                    request=request,
                    item=item,
                    semaphore=semaphore,
                )
            )
            for item in planned
        ]
        done, pending = await asyncio.wait(tasks, timeout=deadline_seconds)
        outcomes: list[ProviderCollectionOutcome] = []
        for task in done:
            outcomes.append(task.result())
        if pending:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            completed = _aware_utc(self.clock())
            pending_items = {
                id(task): planned[index]
                for index, task in enumerate(tasks)
                if task in pending
            }
            for item in pending_items.values():
                outcomes.append(
                    ProviderCollectionOutcome(
                        plan=item.plan,
                        attempt_outcome=ProviderAttemptOutcome.CANCELLED_BY_DEADLINE,
                        evidence=(),
                        latency_ms=None,
                        started_at=completed,
                        completed_at=completed,
                        deadline_exceeded=True,
                        error_code="CANCELLED_BY_DEADLINE",
                    )
                )
            self._audit(
                stored,
                AuditEventType.VERIFICATION_COLLECTION_DEADLINE_REACHED,
                request.correlation_id,
                [VerificationOrchestrationReason.COLLECTION_DEADLINE_REACHED.value],
            )
        ordered = tuple(
            sorted(
                outcomes,
                key=lambda outcome: (
                    outcome.plan.planned_order,
                    str(outcome.plan.provider_id),
                    outcome.plan.provider_alias,
                ),
            )
        )
        self._audit(
            stored,
            AuditEventType.VERIFICATION_COLLECTION_COMPLETED,
            request.correlation_id,
            [outcome.attempt_outcome.value for outcome in ordered],
            planned_provider_ids=[outcome.plan.provider_id for outcome in ordered],
        )
        return ordered

    async def _collect_one_provider(
        self,
        *,
        stored: VerificationRequest,
        request: VerificationRequestEnvelope,
        item: ProviderExecutionPlanItem,
        semaphore: asyncio.Semaphore,
    ) -> ProviderCollectionOutcome:
        async with semaphore:
            started = _aware_utc(self.clock())
            self._audit(
                stored,
                AuditEventType.PROVIDER_ATTEMPT_STARTED,
                request.correlation_id,
                [ProviderAttemptOutcome.SUCCESS.value],
                provider_id=item.plan.provider_id,
                provider_outcome=ProviderAttemptOutcome.SUCCESS.value,
                planned_order=item.plan.planned_order,
                timeout_ms=item.plan.timeout_ms,
            )
            start_monotonic = time.monotonic()
            provider_request = EvidenceProviderRequest(
                account_id=request.authenticated.account_id,
                verification_request_id=stored.id,
                provider_id=item.plan.provider_id,
                capability=request.material.capability,
                mode=request.material.mode,
                assurance=request.material.assurance,
            )
            try:
                provider_result = await asyncio.wait_for(
                    _collect_adapter(item.provider.adapter, provider_request),
                    timeout=self.collection_config.per_provider_timeout.total_seconds(),
                )
            except TimeoutError:
                return self._provider_outcome(
                    item=item,
                    started=started,
                    start_monotonic=start_monotonic,
                    outcome=ProviderAttemptOutcome.TIMEOUT,
                    evidence=(),
                    error_code="TIMEOUT",
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                return self._provider_outcome(
                    item=item,
                    started=started,
                    start_monotonic=start_monotonic,
                    outcome=ProviderAttemptOutcome.SYSTEM_FAILURE,
                    evidence=(),
                    error_code="SYSTEM_FAILURE",
                )
            return self._provider_outcome(
                item=item,
                started=started,
                start_monotonic=start_monotonic,
                outcome=provider_result.attempt_outcome,
                evidence=provider_result.evidence,
                latency_ms=provider_result.latency_ms,
            )

    def _provider_outcome(
        self,
        *,
        item: ProviderExecutionPlanItem,
        started: datetime,
        start_monotonic: float,
        outcome: ProviderAttemptOutcome,
        evidence: tuple[ProviderEvidencePayload, ...],
        latency_ms: int | None = None,
        error_code: str | None = None,
    ) -> ProviderCollectionOutcome:
        completed = _aware_utc(self.clock())
        measured_latency = max(0, int((time.monotonic() - start_monotonic) * 1000))
        return ProviderCollectionOutcome(
            plan=item.plan,
            attempt_outcome=outcome,
            evidence=evidence,
            latency_ms=latency_ms if latency_ms is not None else measured_latency,
            started_at=started,
            completed_at=completed,
            error_code=error_code,
        )

    def _normalize_and_lineage(
        self,
        *,
        stored: VerificationRequest,
        provider: ProviderPlan,
        provider_result: ProviderEvidenceResult,
        correlation_id: UUID,
        accepted: list[InertEvidence],
        stances: list[EvidenceStanceInput],
        lineage_versions: set[str],
    ) -> bool:
        provider_accepted = False
        for payload in provider_result.evidence:
            self._transition(
                stored,
                VerificationLifecyclePhase.EVIDENCE_NORMALIZATION,
                correlation_id,
                [VerificationLifecyclePhase.EVIDENCE_NORMALIZATION.value],
            )
            try:
                inert = self.evidence_normalizer.normalize(
                    EvidenceNormalizationInput(
                        account_id=stored.account_id,
                        verification_request_id=stored.id,
                        provider_id=provider.provider_id,
                        provider_alias=provider.provider_alias,
                        source_uri=payload.source_uri,
                        source_class=payload.source_class,
                        content_type=payload.content_type,
                        body=payload.body,
                        observed_at=payload.observed_at,
                        authority_metadata=payload.authority_metadata,
                        lineage_metadata=payload.lineage_metadata,
                    ),
                    correlation_id=correlation_id,
                )
            except EvidenceNormalizationError:
                self._audit(
                    stored,
                    AuditEventType.EVIDENCE_REJECTED,
                    correlation_id,
                    [VerificationOrchestrationReason.EVIDENCE_REJECTED.value],
                    provider_id=provider.provider_id,
                )
                continue
            self._transition(
                stored,
                VerificationLifecyclePhase.LINEAGE_ANALYSIS,
                correlation_id,
                [VerificationLifecyclePhase.LINEAGE_ANALYSIS.value],
            )
            lineage = self.lineage_service.record_lineage(
                EvidenceLineageInput(
                    evidence_id=inert.evidence_id,
                    account_id=inert.account_id,
                    verification_request_id=inert.verification_request_id,
                    provider_id=inert.provider_id,
                    source_reference=inert.source_uri,
                    source_class=inert.source_class,
                    parent_evidence_ids=payload.parent_evidence_ids,
                    origin_reference=payload.origin_reference,
                    lineage_type=payload.lineage_type,
                    publisher_identity=payload.publisher_identity,
                    canonical_source_identity=payload.canonical_source_identity,
                    observed_at=inert.observed_at,
                    lineage_metadata=payload.lineage_metadata,
                ),
                correlation_id=correlation_id,
            )
            lineage_versions.add(lineage.lineage_version)
            accepted.append(inert)
            stances.append(
                EvidenceStanceInput(
                    evidence_id=inert.evidence_id,
                    stance=payload.stance,
                    coverage_basis_points=payload.coverage_basis_points,
                )
            )
            provider_accepted = True
        if provider_accepted:
            self._audit(
                stored,
                AuditEventType.VERIFICATION_LINEAGE_COMPLETED,
                correlation_id,
                [VerificationLifecyclePhase.LINEAGE_ANALYSIS.value],
                provider_id=provider.provider_id,
            )
        return provider_accepted

    def _create_or_replay_request(
        self,
        request: VerificationRequestEnvelope,
        fingerprint: str,
        now: datetime,
    ) -> tuple[VerificationRequest, bool]:
        existing = self.session.scalar(
            select(VerificationRequest).where(
                VerificationRequest.account_id == request.authenticated.account_id,
                VerificationRequest.idempotency_key == request.idempotency_key,
            )
        )
        if existing is not None:
            self._validate_replay(existing, fingerprint, request.correlation_id)
            return existing, True
        stored = VerificationRequest(
            id=uuid4(),
            account_id=request.authenticated.account_id,
            request_id=uuid4(),
            agent_id=request.authenticated.agent_id,
            mode=request.material.mode.value,
            requested_assurance=request.material.assurance.value,
            claim_hash=_hash_canonical(request.material.claim),
            subject_hash=_hash_canonical(request.material.subject),
            idempotency_key=request.idempotency_key,
            request_fingerprint=fingerprint,
            lifecycle_state=VerificationLifecyclePhase.RECEIVED.value,
            request_config_version=request.material.request_config_version,
            lifecycle_metadata={
                "capability": request.material.capability.value,
                "providers": [str(provider_id) for provider_id in request.material.provider_ids],
            },
        )
        self.session.add(stored)
        try:
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            replayed = self.session.scalar(
                select(VerificationRequest).where(
                    VerificationRequest.account_id == request.authenticated.account_id,
                    VerificationRequest.idempotency_key == request.idempotency_key,
                )
            )
            if replayed is None:
                raise
            self._validate_replay(replayed, fingerprint, request.correlation_id)
            return replayed, True
        self._audit(
            stored,
            AuditEventType.VERIFICATION_RECEIVED,
            request.correlation_id,
            [VerificationLifecyclePhase.RECEIVED.value],
            now=now,
        )
        return stored, False

    def _validate_replay(
        self,
        stored: VerificationRequest,
        fingerprint: str,
        correlation_id: UUID,
    ) -> None:
        if stored.request_fingerprint != fingerprint:
            self._audit(
                stored,
                AuditEventType.VERIFICATION_IDEMPOTENCY_CONFLICT,
                correlation_id,
                [VerificationOrchestrationReason.IDEMPOTENCY_CONFLICT.value],
            )
            raise VerificationIdempotencyConflict(
                VerificationOrchestrationReason.IDEMPOTENCY_CONFLICT.value
            )

    def _replay_result(
        self,
        stored: VerificationRequest,
        fingerprint: str,
        correlation_id: UUID,
    ) -> VerificationOrchestrationResult:
        result_model = self._latest_result(stored)
        self._audit(
            stored,
            AuditEventType.VERIFICATION_IDEMPOTENT_REPLAY,
            correlation_id,
            [VerificationOrchestrationReason.IDEMPOTENT_REPLAY.value],
        )
        return VerificationOrchestrationResult(
            verification_request_id=stored.id,
            account_id=stored.account_id,
            status=(
                VerificationStatus(result_model.status)
                if result_model is not None
                else VerificationStatus.SYSTEM_FAILURE
            ),
            lifecycle_state=VerificationLifecyclePhase(stored.lifecycle_state),
            evidence_score=None,
            verification_result_id=result_model.id if result_model is not None else None,
            request_fingerprint=fingerprint,
            idempotent_replay=True,
            reason_codes=tuple(result_model.reason_codes if result_model else []),
            evidence_ids_used=tuple(
                UUID(str(value))
                for value in (result_model.evidence_ids_used if result_model else [])
            ),
            evidence_ids_excluded=tuple(
                UUID(str(value))
                for value in (result_model.evidence_ids_excluded if result_model else [])
            ),
            providers_contributed=tuple(
                UUID(str(value))
                for value in _metadata_list(stored.lifecycle_metadata, "providers_contributed")
            ),
            providers_failed=tuple(
                UUID(str(value))
                for value in _metadata_list(stored.lifecycle_metadata, "providers_failed")
            ),
            scoring_version=result_model.evidence_score_version if result_model else None,
            lineage_versions=tuple(
                str(value)
                for value in _metadata_list(stored.lifecycle_metadata, "lineage_versions")
            ),
        )

    def _provider_failed(
        self,
        stored: VerificationRequest,
        fingerprint: str,
        correlation_id: UUID,
        providers_failed: list[UUID],
    ) -> VerificationOrchestrationResult:
        score = self.scoring_service.score(
            account_id=stored.account_id,
            verification_request_id=stored.id,
            evidence_ids=(),
            stances=(),
            correlation_id=correlation_id,
            operational_status_override=VerificationStatus.PROVIDER_FAILED,
        )
        result_model = self._latest_result(stored)
        self._complete(
            stored=stored,
            score=score,
            result_model=result_model,
            request_fingerprint=fingerprint,
            correlation_id=correlation_id,
            providers_contributed=(),
            providers_failed=tuple(providers_failed),
            lineage_versions=(),
        )
        return VerificationOrchestrationResult(
            verification_request_id=stored.id,
            account_id=stored.account_id,
            status=VerificationStatus.PROVIDER_FAILED,
            lifecycle_state=VerificationLifecyclePhase.COMPLETED,
            evidence_score=score,
            verification_result_id=result_model.id if result_model is not None else None,
            request_fingerprint=fingerprint,
            idempotent_replay=False,
            reason_codes=score.reason_codes,
            evidence_ids_used=(),
            evidence_ids_excluded=(),
            providers_contributed=(),
            providers_failed=tuple(providers_failed),
            scoring_version=score.evidence_score_version,
            lineage_versions=(),
        )

    def _system_failure(
        self,
        stored: VerificationRequest,
        fingerprint: str,
        correlation_id: UUID,
    ) -> VerificationOrchestrationResult:
        self._fail(stored, correlation_id, [VerificationOrchestrationReason.SYSTEM_FAILURE.value])
        score = self.scoring_service.score(
            account_id=stored.account_id,
            verification_request_id=stored.id,
            evidence_ids=(),
            stances=(),
            correlation_id=correlation_id,
            operational_status_override=VerificationStatus.SYSTEM_FAILURE,
        )
        result_model = self._latest_result(stored)
        return VerificationOrchestrationResult(
            verification_request_id=stored.id,
            account_id=stored.account_id,
            status=VerificationStatus.SYSTEM_FAILURE,
            lifecycle_state=VerificationLifecyclePhase.FAILED,
            evidence_score=score,
            verification_result_id=result_model.id if result_model is not None else None,
            request_fingerprint=fingerprint,
            idempotent_replay=False,
            reason_codes=score.reason_codes,
            evidence_ids_used=(),
            evidence_ids_excluded=(),
            providers_contributed=(),
            providers_failed=(),
            scoring_version=score.evidence_score_version,
            lineage_versions=(),
        )

    def _complete(
        self,
        *,
        stored: VerificationRequest,
        score: EvidenceScore,
        result_model: VerificationResult | None,
        request_fingerprint: str,
        correlation_id: UUID,
        providers_contributed: tuple[UUID, ...],
        providers_failed: tuple[UUID, ...],
        lineage_versions: tuple[str, ...],
    ) -> None:
        if stored.lifecycle_state == VerificationLifecyclePhase.COMPLETED.value:
            return
        metadata = dict(stored.lifecycle_metadata)
        metadata.update(
            {
                "providers_contributed": [str(value) for value in providers_contributed],
                "providers_failed": [str(value) for value in providers_failed],
                "scoring_version": score.evidence_score_version,
                "lineage_versions": list(lineage_versions),
                "verification_result_id": (
                    str(result_model.id) if result_model is not None else None
                ),
            }
        )
        stored.lifecycle_metadata = metadata
        stored.lifecycle_state = VerificationLifecyclePhase.COMPLETED.value
        stored.completed_at = _aware_utc(self.clock())
        self.session.flush()
        self._audit(
            stored,
            AuditEventType.VERIFICATION_EVIDENCE_ASSESSMENT_COMPLETED,
            correlation_id,
            [score.verification_status.value],
            final_score=score.final_score,
        )
        self._audit(
            stored,
            AuditEventType.VERIFICATION_COMPLETED,
            correlation_id,
            [score.verification_status.value],
            final_score=score.final_score,
        )

    def _fail(
        self,
        stored: VerificationRequest,
        correlation_id: UUID,
        reason_codes: list[str],
    ) -> None:
        stored.lifecycle_state = VerificationLifecyclePhase.FAILED.value
        stored.failed_at = _aware_utc(self.clock())
        self.session.flush()
        self._audit(stored, AuditEventType.VERIFICATION_FAILED, correlation_id, reason_codes)

    def _transition(
        self,
        stored: VerificationRequest,
        state: VerificationLifecyclePhase,
        correlation_id: UUID,
        reason_codes: list[str],
    ) -> None:
        if stored.lifecycle_state == VerificationLifecyclePhase.COMPLETED.value:
            return
        stored.lifecycle_state = state.value
        self.session.flush()
        self._audit(stored, AuditEventType.REQUEST_ACCEPTED, correlation_id, reason_codes)

    def _persist_provider_attempt(
        self,
        *,
        stored: VerificationRequest,
        outcome: ProviderCollectionOutcome,
        correlation_id: UUID,
    ) -> None:
        health_effect = (
            "NO_HEALTH_EFFECT"
            if outcome.attempt_outcome
            in {
                ProviderAttemptOutcome.SYSTEM_FAILURE,
                ProviderAttemptOutcome.CANCELLED_BY_DEADLINE,
                ProviderAttemptOutcome.CIRCUIT_OPEN,
                ProviderAttemptOutcome.DISABLED,
            }
            else "AFFECTS_PROVIDER_HEALTH"
        )
        row = ProviderAttempt(
            id=uuid4(),
            account_id=stored.account_id,
            provider_id=outcome.plan.provider_id,
            verification_request_id=stored.id,
            authorization_request_id=None,
            provider_health="UNKNOWN",
            status=outcome.attempt_outcome.value,
            error_code=outcome.error_code,
            capability=outcome.plan.capability.value,
            attempt_number=1,
            planned_order=outcome.plan.planned_order,
            started_at=outcome.started_at,
            completed_at=outcome.completed_at,
            latency_ms=outcome.latency_ms,
            timeout_ms=outcome.plan.timeout_ms,
            deadline_exceeded=outcome.deadline_exceeded,
            health_effect=health_effect,
            attempt_metadata={
                "execution_plan_version": outcome.plan.config_version,
                "billing_mode": outcome.plan.billing_mode.value,
                "execution_mode": outcome.plan.execution_mode.value,
                "provider_alias": outcome.plan.provider_alias,
                "rights_version": outcome.plan.rights_version,
            },
        )
        self.session.add(row)
        self.session.flush()
        event_type = {
            ProviderAttemptOutcome.SUCCESS: AuditEventType.PROVIDER_ATTEMPT_SUCCEEDED,
            ProviderAttemptOutcome.TIMEOUT: AuditEventType.PROVIDER_ATTEMPT_TIMED_OUT,
            ProviderAttemptOutcome.CANCELLED_BY_DEADLINE: (
                AuditEventType.PROVIDER_ATTEMPT_TIMED_OUT
            ),
            ProviderAttemptOutcome.RATE_LIMITED: AuditEventType.PROVIDER_ATTEMPT_RATE_LIMITED,
        }.get(outcome.attempt_outcome, AuditEventType.PROVIDER_ATTEMPT_FAILED)
        self._audit(
            stored,
            event_type,
            correlation_id,
            [outcome.attempt_outcome.value],
            provider_id=outcome.plan.provider_id,
            provider_outcome=outcome.attempt_outcome.value,
            provider_attempt_id=row.id,
            planned_order=outcome.plan.planned_order,
            attempt_number=1,
            timeout_ms=outcome.plan.timeout_ms,
            deadline_exceeded=outcome.deadline_exceeded,
            latency_ms=outcome.latency_ms,
            health_effect=health_effect,
        )

    def _persist_skipped_provider_attempt(
        self,
        *,
        stored: VerificationRequest,
        provider: ProviderPlan,
        planned_order: int,
        reason: str,
        correlation_id: UUID,
    ) -> None:
        row = ProviderAttempt(
            id=uuid4(),
            account_id=stored.account_id,
            provider_id=provider.provider_id,
            verification_request_id=stored.id,
            authorization_request_id=None,
            provider_health=reason,
            status=reason,
            error_code=reason,
            capability=stored.lifecycle_metadata.get("capability")
            if isinstance(stored.lifecycle_metadata.get("capability"), str)
            else None,
            attempt_number=0,
            planned_order=planned_order,
            started_at=None,
            completed_at=None,
            latency_ms=None,
            timeout_ms=None,
            deadline_exceeded=False,
            health_effect="NO_EXECUTION",
            attempt_metadata={
                "execution_plan_version": VERIFICATION_EXECUTION_PLAN_VERSION,
                "provider_alias": provider.provider_alias,
            },
        )
        self.session.add(row)
        self.session.flush()
        self._audit(
            stored,
            AuditEventType.PROVIDER_ATTEMPT_FAILED,
            correlation_id,
            [reason],
            provider_id=provider.provider_id,
            provider_attempt_id=row.id,
            planned_order=planned_order,
            attempt_number=0,
            health_effect="NO_EXECUTION",
        )

    def _audit(
        self,
        stored: VerificationRequest,
        event_type: AuditEventType,
        correlation_id: UUID,
        reason_codes: list[str],
        *,
        provider_id: UUID | None = None,
        final_score: int | None = None,
        now: datetime | None = None,
        provider_outcome: str | None = None,
        provider_attempt_id: UUID | None = None,
        planned_provider_ids: list[UUID] | None = None,
        planned_order: int | None = None,
        attempt_number: int | None = None,
        timeout_ms: int | None = None,
        deadline_exceeded: bool | None = None,
        latency_ms: int | None = None,
        health_effect: str | None = None,
    ) -> None:
        payload: dict[str, object] = {
            "request_id": stored.request_id,
            "request_fingerprint": stored.request_fingerprint,
            "idempotency_key": stored.idempotency_key,
            "lifecycle_state": stored.lifecycle_state,
            "request_config_version": stored.request_config_version,
            "capability": str(stored.lifecycle_metadata.get("capability", "")),
            "reason_codes": reason_codes,
        }
        if provider_id is not None:
            payload["provider_id"] = provider_id
        if provider_outcome is not None:
            payload["provider_outcome"] = provider_outcome
        if provider_attempt_id is not None:
            payload["provider_attempt_id"] = provider_attempt_id
        if planned_provider_ids is not None:
            payload["planned_provider_ids"] = planned_provider_ids
            payload["execution_plan_version"] = VERIFICATION_EXECUTION_PLAN_VERSION
            payload["max_providers"] = self.collection_config.max_providers
            payload["max_concurrency"] = self.collection_config.max_concurrency
            payload["overall_deadline_ms"] = _milliseconds(
                self.collection_config.overall_deadline
            )
        if planned_order is not None:
            payload["planned_order"] = planned_order
        if attempt_number is not None:
            payload["attempt_number"] = attempt_number
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        if deadline_exceeded is not None:
            payload["deadline_exceeded"] = deadline_exceeded
        if latency_ms is not None:
            payload["latency_ms"] = latency_ms
        if health_effect is not None:
            payload["health_effect"] = health_effect
        if final_score is not None:
            payload["final_score"] = final_score
        if now is not None:
            payload["timestamp"] = now
        self.audit_service.append_event(
            account_id=stored.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=stored.id,
            payload=payload,
        )

    def _latest_result(self, stored: VerificationRequest) -> VerificationResult | None:
        return self.session.scalars(
            select(VerificationResult)
            .where(
                VerificationResult.account_id == stored.account_id,
                VerificationResult.verification_request_id == stored.id,
            )
            .order_by(VerificationResult.created_at.desc(), VerificationResult.id.desc())
        ).first()


def verification_request_fingerprint(material: VerificationMaterial) -> str:
    provider_ids = sorted(str(provider_id) for provider_id in material.provider_ids)
    canonical = canonical_material_json(
        material={
            "assurance": material.assurance.value,
            "capability": material.capability.value,
            "claim": material.claim,
            "mode": material.mode.value,
            "provider_ids": provider_ids,
            "request_config_version": material.request_config_version,
            "subject": material.subject,
        },
        action_schema_version=VERIFICATION_REQUEST_SCHEMA_VERSION,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _hash_canonical(value: Mapping[str, object]) -> str:
    return hashlib.sha256(
        canonical_material_json(
            material=value,
            action_schema_version=VERIFICATION_REQUEST_SCHEMA_VERSION,
        ).encode("utf-8")
    ).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise VerificationOrchestrationError("verification timestamps must be timezone-aware")
    return value.astimezone(UTC)


async def _collect_adapter(
    adapter: EvidenceProvider | AsyncEvidenceProvider,
    request: EvidenceProviderRequest,
) -> ProviderEvidenceResult:
    result = adapter.collect(request)
    if inspect.isawaitable(result):
        return await result
    return result


def _provider_plan_for_outcome(
    providers: tuple[ProviderPlan, ...],
    outcome: ProviderCollectionOutcome,
) -> ProviderPlan:
    for provider in providers:
        if provider.provider_id == outcome.plan.provider_id:
            return provider
    raise VerificationOrchestrationError("provider plan missing for outcome")


def _milliseconds(value: timedelta) -> int:
    return int(value.total_seconds() * 1000)


def _validate_collection_config(config: ProviderCollectionConfig) -> None:
    if not 1 <= config.max_providers <= 32:
        raise VerificationOrchestrationError(
            VerificationOrchestrationReason.CONFIGURATION_UNSAFE.value
        )
    if not 1 <= config.max_concurrency <= config.max_providers:
        raise VerificationOrchestrationError(
            VerificationOrchestrationReason.CONFIGURATION_UNSAFE.value
        )
    if config.max_attempts_per_provider != 1:
        raise VerificationOrchestrationError(
            VerificationOrchestrationReason.CONFIGURATION_UNSAFE.value
        )
    if not 0 < config.per_provider_timeout.total_seconds() <= 60:
        raise VerificationOrchestrationError(
            VerificationOrchestrationReason.CONFIGURATION_UNSAFE.value
        )
    if not 0 < config.overall_deadline.total_seconds() <= 300:
        raise VerificationOrchestrationError(
            VerificationOrchestrationReason.CONFIGURATION_UNSAFE.value
        )


def _metadata_list(metadata: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = metadata.get(key)
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


__all__ = [
    "AuthenticatedVerificationContext",
    "CrossTenantVerificationAccess",
    "AsyncEvidenceProvider",
    "EvidenceProvider",
    "EvidenceProviderRequest",
    "PlannedProviderCollection",
    "ProviderCollectionConfig",
    "ProviderCollectionOutcome",
    "ProviderEvidencePayload",
    "ProviderEvidenceResult",
    "ProviderPlan",
    "VERIFICATION_EXECUTION_PLAN_VERSION",
    "VERIFICATION_ORCHESTRATION_VERSION",
    "VERIFICATION_REQUEST_SCHEMA_VERSION",
    "VerificationLifecyclePhase",
    "VerificationMaterial",
    "VerificationOrchestrationError",
    "VerificationOrchestrationReason",
    "VerificationOrchestrationResult",
    "VerificationOrchestrator",
    "VerificationRequestEnvelope",
    "VerificationIdempotencyConflict",
    "verification_request_fingerprint",
]
