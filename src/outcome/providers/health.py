from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Provider, ProviderMetric
from outcome.domain import ProviderHealth
from outcome.pricing.service import CapabilityName
from outcome.providers.rights import ProviderRightsAuthorizationResult

METRICS_VERSION = "provider-health-v1"


class CircuitState(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class ProviderAttemptOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    RATE_LIMITED = "RATE_LIMITED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    DISABLED = "DISABLED"
    CANCELLED_BY_DEADLINE = "CANCELLED_BY_DEADLINE"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"


class ProviderHealthReason(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED_BY_FAILURES = "DEGRADED_BY_FAILURES"
    CIRCUIT_OPEN_FAILURE_THRESHOLD = "CIRCUIT_OPEN_FAILURE_THRESHOLD"
    CIRCUIT_OPEN_TIMEOUT_THRESHOLD = "CIRCUIT_OPEN_TIMEOUT_THRESHOLD"
    CIRCUIT_COOLDOWN_ACTIVE = "CIRCUIT_COOLDOWN_ACTIVE"
    CIRCUIT_PROBE_READY = "CIRCUIT_PROBE_READY"
    CIRCUIT_RECOVERED = "CIRCUIT_RECOVERED"
    MANUALLY_DISABLED = "MANUALLY_DISABLED"
    PROVIDER_NOT_FOUND = "PROVIDER_NOT_FOUND"
    HEALTH_BLOCKED = "HEALTH_BLOCKED"


class ProviderHealthError(ValueError):
    pass


class CrossTenantProviderHealthAccess(PermissionError):
    pass


@dataclass(frozen=True)
class ProviderHealthConfig:
    failure_threshold: int = 3
    timeout_threshold: int = 2
    degraded_failure_threshold: int = 1
    cooldown_seconds: int = 60
    window_seconds: int = 300


@dataclass(frozen=True)
class ProviderHealthRequest:
    account_id: UUID
    provider_id: UUID
    capability: CapabilityName
    evaluated_at: datetime | None = None


@dataclass(frozen=True)
class ProviderHealthResult:
    provider_id: UUID
    capability: CapabilityName
    provider_health: ProviderHealth
    circuit_state: CircuitState
    reason_code: ProviderHealthReason
    retry_after: datetime | None
    next_probe_at: datetime | None
    metrics_version: str
    window_start: datetime
    window_end: datetime
    request_count: int
    success_count: int
    failure_count: int
    timeout_count: int
    consecutive_failures: int

    @property
    def usable(self) -> bool:
        return self.provider_health not in {
            ProviderHealth.CIRCUIT_OPEN,
            ProviderHealth.DISABLED,
        }


@dataclass(frozen=True)
class ProviderEligibilityResult:
    allowed: bool
    provider_id: UUID | None
    capability: CapabilityName
    provider_health: ProviderHealth | None
    rights_allowed: bool
    reason_code: str


class ProviderHealthService:
    def __init__(
        self,
        session: Session,
        audit_service: AuditService | None = None,
        *,
        config: ProviderHealthConfig | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.session = session
        self.audit_service = audit_service
        self.config = config or ProviderHealthConfig()
        self.clock = clock or (lambda: datetime.now(UTC))

    def evaluate(
        self,
        request: ProviderHealthRequest,
        *,
        correlation_id: UUID,
    ) -> ProviderHealthResult:
        now = _aware_utc(request.evaluated_at or self.clock())
        provider = self._require_provider(request.account_id, request.provider_id)
        metric = self._metric_or_new(
            account_id=request.account_id,
            provider_id=request.provider_id,
            capability=request.capability,
            now=now,
        )
        result = self._result_from_metric(
            provider=provider,
            metric=metric,
            capability=request.capability,
            now=now,
        )
        self._audit_result(
            account_id=request.account_id,
            result=result,
            correlation_id=correlation_id,
            event_type=(
                AuditEventType.PROVIDER_USE_BLOCKED_BY_HEALTH
                if not result.usable
                else AuditEventType.PROVIDER_HEALTH_EVALUATED
            ),
        )
        return result

    def record_attempt(
        self,
        *,
        account_id: UUID,
        provider_id: UUID,
        capability: CapabilityName,
        outcome: ProviderAttemptOutcome,
        correlation_id: UUID,
        latency_ms: int | None = None,
        occurred_at: datetime | None = None,
    ) -> ProviderHealthResult:
        now = _aware_utc(occurred_at or self.clock())
        if latency_ms is not None and latency_ms < 0:
            raise ProviderHealthError("latency_ms must be non-negative")
        provider = self._require_provider(account_id, provider_id)
        metric = self._metric_or_new(
            account_id=account_id,
            provider_id=provider_id,
            capability=capability,
            now=now,
            for_update=True,
        )
        old_health = ProviderHealth(metric.current_health)
        old_circuit = CircuitState(metric.circuit_state)
        if (
            outcome is ProviderAttemptOutcome.SUCCESS
            and not metric.manually_disabled
            and old_circuit is CircuitState.CLOSED
        ):
            bounded_latency = min(latency_ms, 300_000) if latency_ms is not None else None
            values: dict[str, object] = {
                "request_count": ProviderMetric.request_count + 1,
                "success_count": ProviderMetric.success_count + 1,
                "consecutive_failures": 0,
                "window_end": now,
                "metric_value": ProviderMetric.metric_value + 1,
                "current_health": ProviderHealth.HEALTHY.value,
                "circuit_state": CircuitState.CLOSED.value,
            }
            if bounded_latency is not None:
                values["latency_count"] = ProviderMetric.latency_count + 1
                values["latency_total_ms"] = ProviderMetric.latency_total_ms + bounded_latency
                values["latency_max_ms"] = bounded_latency
            self.session.execute(
                update(ProviderMetric)
                .where(ProviderMetric.id == metric.id)
                .values(**values)
            )
            self.session.flush()
            self.session.refresh(metric)
            provider.health = metric.current_health
            result = self._result_from_metric(
                provider=provider,
                metric=metric,
                capability=capability,
                now=now,
            )
            self._audit_transition(
                account_id=account_id,
                result=result,
                old_health=old_health,
                old_circuit=old_circuit,
                correlation_id=correlation_id,
            )
            return result
        metric.request_count += 1
        metric.window_end = now
        metric.metric_value = metric.request_count
        if latency_ms is not None:
            bounded_latency = min(latency_ms, 300_000)
            metric.latency_count += 1
            metric.latency_total_ms += bounded_latency
            metric.latency_max_ms = max(metric.latency_max_ms, bounded_latency)

        if outcome is ProviderAttemptOutcome.SUCCESS:
            metric.success_count += 1
            metric.consecutive_failures = 0
            if old_circuit is CircuitState.OPEN and self._retry_ready(metric, now):
                metric.circuit_state = CircuitState.CLOSED.value
                metric.current_health = ProviderHealth.HEALTHY.value
                metric.circuit_opened_at = None
                metric.circuit_retry_at = None
            elif not metric.manually_disabled:
                metric.circuit_state = CircuitState.CLOSED.value
                metric.current_health = ProviderHealth.HEALTHY.value
        elif outcome is ProviderAttemptOutcome.SYSTEM_FAILURE:
            metric.system_failure_count += 1
        elif outcome is ProviderAttemptOutcome.CANCELLED_BY_DEADLINE:
            metric.timeout_count += 1
        elif outcome in {
            ProviderAttemptOutcome.CIRCUIT_OPEN,
            ProviderAttemptOutcome.DISABLED,
        }:
            pass
        else:
            metric.failure_count += 1
            metric.consecutive_failures += 1
            if outcome is ProviderAttemptOutcome.TIMEOUT:
                metric.timeout_count += 1
            if outcome is ProviderAttemptOutcome.RATE_LIMITED:
                metric.rate_limited_count += 1
            self._apply_provider_failure(metric=metric, now=now)

        if metric.manually_disabled:
            metric.current_health = ProviderHealth.DISABLED.value
            metric.circuit_state = CircuitState.OPEN.value
        provider.health = metric.current_health
        self.session.flush()
        result = self._result_from_metric(
            provider=provider,
            metric=metric,
            capability=capability,
            now=now,
        )
        self._audit_transition(
            account_id=account_id,
            result=result,
            old_health=old_health,
            old_circuit=old_circuit,
            correlation_id=correlation_id,
        )
        return result

    def manual_disable(
        self,
        *,
        account_id: UUID,
        provider_id: UUID,
        capability: CapabilityName,
        correlation_id: UUID,
        disabled_at: datetime | None = None,
    ) -> ProviderHealthResult:
        now = _aware_utc(disabled_at or self.clock())
        provider = self._require_provider(account_id, provider_id)
        metric = self._metric_or_new(
            account_id=account_id,
            provider_id=provider_id,
            capability=capability,
            now=now,
            for_update=True,
        )
        metric.manually_disabled = True
        metric.current_health = ProviderHealth.DISABLED.value
        metric.circuit_state = CircuitState.OPEN.value
        metric.circuit_opened_at = now
        metric.circuit_retry_at = None
        metric.window_end = now
        provider.health = ProviderHealth.DISABLED.value
        self.session.flush()
        result = self._result_from_metric(
            provider=provider,
            metric=metric,
            capability=capability,
            now=now,
        )
        self._audit_result(
            account_id=account_id,
            result=result,
            correlation_id=correlation_id,
            event_type=AuditEventType.PROVIDER_MANUALLY_DISABLED,
        )
        return result

    def _apply_provider_failure(self, *, metric: ProviderMetric, now: datetime) -> None:
        if (
            metric.consecutive_failures >= self.config.failure_threshold
            or metric.timeout_count >= self.config.timeout_threshold
        ):
            metric.current_health = ProviderHealth.CIRCUIT_OPEN.value
            metric.circuit_state = CircuitState.OPEN.value
            metric.circuit_opened_at = metric.circuit_opened_at or now
            metric.circuit_retry_at = now + timedelta(seconds=self.config.cooldown_seconds)
        elif metric.consecutive_failures >= self.config.degraded_failure_threshold:
            metric.current_health = ProviderHealth.DEGRADED.value
            metric.circuit_state = CircuitState.CLOSED.value

    def _result_from_metric(
        self,
        *,
        provider: Provider,
        metric: ProviderMetric,
        capability: CapabilityName,
        now: datetime,
    ) -> ProviderHealthResult:
        health = ProviderHealth(metric.current_health)
        circuit = CircuitState(metric.circuit_state)
        retry_at = _db_timestamp_utc(metric.circuit_retry_at)
        reason = ProviderHealthReason.HEALTHY
        if metric.manually_disabled or health is ProviderHealth.DISABLED:
            health = ProviderHealth.DISABLED
            circuit = CircuitState.OPEN
            reason = ProviderHealthReason.MANUALLY_DISABLED
        elif health is ProviderHealth.CIRCUIT_OPEN:
            if retry_at is not None and retry_at <= now:
                circuit = CircuitState.HALF_OPEN
                reason = ProviderHealthReason.CIRCUIT_PROBE_READY
            else:
                reason = ProviderHealthReason.CIRCUIT_COOLDOWN_ACTIVE
        elif health is ProviderHealth.DEGRADED:
            reason = ProviderHealthReason.DEGRADED_BY_FAILURES
        provider.health = health.value
        return ProviderHealthResult(
            provider_id=provider.id,
            capability=capability,
            provider_health=health,
            circuit_state=circuit,
            reason_code=reason,
            retry_after=retry_at if health is ProviderHealth.CIRCUIT_OPEN else None,
            next_probe_at=retry_at if health is ProviderHealth.CIRCUIT_OPEN else None,
            metrics_version=metric.metrics_version,
            window_start=_required_db_timestamp_utc(metric.window_start),
            window_end=_required_db_timestamp_utc(metric.window_end),
            request_count=metric.request_count,
            success_count=metric.success_count,
            failure_count=metric.failure_count,
            timeout_count=metric.timeout_count,
            consecutive_failures=metric.consecutive_failures,
        )

    def _metric_or_new(
        self,
        *,
        account_id: UUID,
        provider_id: UUID,
        capability: CapabilityName,
        now: datetime,
        for_update: bool = False,
    ) -> ProviderMetric:
        statement = select(ProviderMetric).where(
            ProviderMetric.account_id == account_id,
            ProviderMetric.provider_id == provider_id,
            ProviderMetric.capability == capability.value,
        )
        if for_update:
            statement = statement.with_for_update()
        metric = self.session.scalar(statement)
        if metric is not None:
            return metric
        metric = ProviderMetric(
            id=uuid4(),
            account_id=account_id,
            provider_id=provider_id,
            provider_health=ProviderHealth.HEALTHY.value,
            metric_name="provider_health_window",
            metric_value=0,
            dimensions={},
            capability=capability.value,
            metrics_version=METRICS_VERSION,
            window_start=now,
            window_end=now,
            request_count=0,
            success_count=0,
            failure_count=0,
            timeout_count=0,
            rate_limited_count=0,
            system_failure_count=0,
            consecutive_failures=0,
            latency_count=0,
            latency_total_ms=0,
            latency_max_ms=0,
            current_health=ProviderHealth.HEALTHY.value,
            circuit_state=CircuitState.CLOSED.value,
            circuit_opened_at=None,
            circuit_retry_at=None,
            manually_disabled=False,
        )
        self.session.add(metric)
        self.session.flush()
        return metric

    def _require_provider(self, account_id: UUID, provider_id: UUID) -> Provider:
        provider = self.session.scalar(
            select(Provider).where(
                Provider.account_id == account_id,
                Provider.id == provider_id,
            )
        )
        if provider is not None:
            return provider
        cross_tenant = self.session.get(Provider, provider_id)
        if cross_tenant is not None and cross_tenant.account_id != account_id:
            raise CrossTenantProviderHealthAccess("provider belongs to a different account")
        raise ProviderHealthError("provider not found")

    def _retry_ready(self, metric: ProviderMetric, now: datetime) -> bool:
        retry_at = _db_timestamp_utc(metric.circuit_retry_at)
        return retry_at is not None and retry_at <= now

    def _audit_transition(
        self,
        *,
        account_id: UUID,
        result: ProviderHealthResult,
        old_health: ProviderHealth,
        old_circuit: CircuitState,
        correlation_id: UUID,
    ) -> None:
        if result.circuit_state is CircuitState.HALF_OPEN:
            event_type = AuditEventType.PROVIDER_CIRCUIT_PROBE_ATTEMPTED
        elif result.provider_health is ProviderHealth.CIRCUIT_OPEN:
            event_type = AuditEventType.PROVIDER_CIRCUIT_OPENED
        elif result.provider_health is ProviderHealth.DEGRADED:
            event_type = AuditEventType.PROVIDER_DEGRADED
        elif (
            old_health is ProviderHealth.CIRCUIT_OPEN
            or old_circuit is CircuitState.OPEN
        ) and result.provider_health is ProviderHealth.HEALTHY:
            event_type = AuditEventType.PROVIDER_CIRCUIT_RECOVERED
        else:
            event_type = AuditEventType.PROVIDER_HEALTH_EVALUATED
        self._audit_result(
            account_id=account_id,
            result=result,
            correlation_id=correlation_id,
            event_type=event_type,
        )

    def _audit_result(
        self,
        *,
        account_id: UUID,
        result: ProviderHealthResult,
        correlation_id: UUID,
        event_type: AuditEventType,
    ) -> None:
        if self.audit_service is None:
            return
        self.audit_service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload={
                "provider_id": result.provider_id,
                "capability": result.capability.value,
                "provider_health": result.provider_health.value,
                "circuit_state": result.circuit_state.value,
                "retry_after": result.retry_after,
                "next_probe_at": result.next_probe_at,
                "metrics_version": result.metrics_version,
                "window_start": result.window_start,
                "window_end": result.window_end,
                "request_count": result.request_count,
                "success_count": result.success_count,
                "failure_count": result.failure_count,
                "timeout_count": result.timeout_count,
                "consecutive_failures": result.consecutive_failures,
                "reason_codes": [result.reason_code.value],
            },
        )


def provider_eligibility(
    *,
    rights: ProviderRightsAuthorizationResult,
    health: ProviderHealthResult,
) -> ProviderEligibilityResult:
    if not rights.allowed:
        return ProviderEligibilityResult(
            allowed=False,
            provider_id=rights.provider_id,
            capability=rights.capability,
            provider_health=health.provider_health,
            rights_allowed=False,
            reason_code=rights.reason_code.value,
        )
    if not health.usable:
        return ProviderEligibilityResult(
            allowed=False,
            provider_id=rights.provider_id,
            capability=rights.capability,
            provider_health=health.provider_health,
            rights_allowed=True,
            reason_code=ProviderHealthReason.HEALTH_BLOCKED.value,
        )
    return ProviderEligibilityResult(
        allowed=True,
        provider_id=rights.provider_id,
        capability=rights.capability,
        provider_health=health.provider_health,
        rights_allowed=True,
        reason_code="ALLOWED",
    )


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProviderHealthError("provider health timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _db_timestamp_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _required_db_timestamp_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "CircuitState",
    "CrossTenantProviderHealthAccess",
    "METRICS_VERSION",
    "ProviderAttemptOutcome",
    "ProviderEligibilityResult",
    "ProviderHealthConfig",
    "ProviderHealthError",
    "ProviderHealthReason",
    "ProviderHealthRequest",
    "ProviderHealthResult",
    "ProviderHealthService",
    "provider_eligibility",
]
