from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlparse
from uuid import UUID

from outcome.audit import AuditEventType, AuditService
from outcome.evidence import EvidenceLineageType, EvidenceStance, SourceClass
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderAttemptOutcome,
    ProviderCredentialMode,
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderRightsRequest,
    ProviderRightsService,
)
from outcome.secrets import CredentialType
from outcome.verification.orchestrator import (
    EvidenceProviderRequest,
    ProviderEvidencePayload,
    ProviderEvidenceResult,
)
from outcome.worker.secrets import (
    SecretMaterial,
    SecretResolutionStatus,
    WorkerProviderExecutionRequest,
    WorkerSecretResolutionService,
)

PROVIDER_EXECUTION_ADAPTER_VERSION = "provider-executor-v1"
MAX_REQUEST_PARAMETER_DEPTH = 4
MAX_REQUEST_PARAMETER_COUNT = 64
MAX_PARAMETER_STRING_LENGTH = 2048
DISALLOWED_PARAMETER_KEYS = frozenset(
    {
        "authorization",
        "authorization_header",
        "cookie",
        "headers",
        "host",
        "url",
        "uri",
    }
)


class ProviderExecutionErrorCode(StrEnum):
    CREDENTIAL_RESOLUTION_FAILED = "CREDENTIAL_RESOLUTION_FAILED"
    DESTINATION_NOT_ALLOWED = "DESTINATION_NOT_ALLOWED"
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    MODE_CONFUSION = "MODE_CONFUSION"
    OVERSIZED_RESPONSE = "OVERSIZED_RESPONSE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    RATE_LIMITED = "RATE_LIMITED"
    RIGHTS_DENIED = "RIGHTS_DENIED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    TIMEOUT = "TIMEOUT"


@dataclass(frozen=True)
class ProviderDestination:
    scheme: str
    hostname: str
    port: int | None = None

    def validate_source_uri(self, source_uri: str) -> bool:
        parsed = urlparse(source_uri)
        if parsed.scheme.lower() != self.scheme.lower():
            return False
        if parsed.hostname is None or parsed.hostname.lower() != self.hostname.lower():
            return False
        return parsed.port == self.port if self.port is not None else parsed.port is None


@dataclass(frozen=True)
class ProviderExecutionEnvelope:
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID
    provider_alias: str
    capability: CapabilityName
    execution_mode: BillingMode
    rights_version: str | None
    requested_region: str
    requested_data_use: ProviderDataUse
    requested_execution_mode: ProviderExecutionMode
    timeout: timedelta
    correlation_id: UUID
    destination: ProviderDestination
    request_parameters: Mapping[str, object]
    secret_ref: str | None = None
    managed_credential_ref: str | None = None
    credential_ref_version: str | None = None
    source_class: SourceClass = SourceClass.UNKNOWN
    stance: EvidenceStance = EvidenceStance.UNKNOWN
    lineage_type: EvidenceLineageType = EvidenceLineageType.UNKNOWN


@dataclass(frozen=True)
class ProviderTransportRequest:
    provider_id: UUID
    capability: CapabilityName
    destination: ProviderDestination
    parameters: Mapping[str, object]
    timeout: timedelta


@dataclass(frozen=True)
class RawProviderResponse:
    status_code: int
    content_type: str
    body: bytes | str
    source_uri: str
    observed_at: datetime


class ProviderTransportTimeout(TimeoutError):
    pass


class ProviderTransportRateLimited(RuntimeError):
    pass


class ProviderTransportFailure(RuntimeError):
    pass


class ProviderTransportSystemFailure(RuntimeError):
    pass


class ProviderTransport(Protocol):
    async def send(
        self,
        request: ProviderTransportRequest,
        credential_material: SecretMaterial,
    ) -> RawProviderResponse:
        raise NotImplementedError


class ManagedCredentialResolver(Protocol):
    def resolve(
        self,
        *,
        credential_ref: str,
        account_id: UUID,
        provider_id: UUID,
    ) -> SecretMaterial:
        raise NotImplementedError


class InMemoryManagedCredentialResolver:
    def __init__(self) -> None:
        self._credentials: dict[tuple[UUID, UUID, str], str] = {}

    def put(
        self,
        *,
        credential_ref: str,
        account_id: UUID,
        provider_id: UUID,
        secret_value: str,
    ) -> None:
        self._credentials[(account_id, provider_id, credential_ref)] = secret_value

    def resolve(
        self,
        *,
        credential_ref: str,
        account_id: UUID,
        provider_id: UUID,
    ) -> SecretMaterial:
        value = self._credentials.get((account_id, provider_id, credential_ref))
        if value is None:
            raise LookupError("managed credential reference not found")
        return SecretMaterial(value, credential_type=CredentialType.API_KEY)


@dataclass(frozen=True)
class ProviderExecutionResult:
    provider_id: UUID
    provider_alias: str
    capability: CapabilityName
    execution_mode: BillingMode
    attempt_outcome: ProviderAttemptOutcome
    latency_ms: int | None
    evidence: tuple[ProviderEvidencePayload, ...]
    reason_code: str
    provenance: dict[str, object]


class ProviderExecutor:
    def __init__(
        self,
        *,
        provider_rights_service: ProviderRightsService,
        transport: ProviderTransport,
        byok_secret_service: WorkerSecretResolutionService | None = None,
        managed_credential_resolver: ManagedCredentialResolver | None = None,
        audit_service: AuditService | None = None,
        max_response_bytes: int = 65_536,
    ) -> None:
        if max_response_bytes <= 0 or max_response_bytes > 1_048_576:
            raise ValueError("max_response_bytes must be between 1 and 1048576")
        self.provider_rights_service = provider_rights_service
        self.transport = transport
        self.byok_secret_service = byok_secret_service
        self.managed_credential_resolver = managed_credential_resolver
        self.audit_service = audit_service
        self.max_response_bytes = max_response_bytes

    async def execute(self, envelope: ProviderExecutionEnvelope) -> ProviderExecutionResult:
        started = time.monotonic()
        try:
            self._validate_envelope(envelope)
        except ValueError:
            return self._rejected(
                envelope,
                ProviderExecutionErrorCode.INVALID_ENVELOPE,
                started,
            )

        self._audit(
            envelope,
            AuditEventType.PROVIDER_EXECUTION_STARTED,
            [AuditEventType.PROVIDER_EXECUTION_STARTED.value],
        )
        rights = self.provider_rights_service.authorize(
            ProviderRightsRequest(
                account_id=envelope.account_id,
                provider_id=envelope.provider_id,
                provider_alias=envelope.provider_alias,
                capability=envelope.capability,
                billing_mode=envelope.execution_mode,
                requested_region=envelope.requested_region,
                requested_data_use=envelope.requested_data_use,
                requested_execution_mode=envelope.requested_execution_mode,
                credential_mode=_credential_mode(envelope.execution_mode),
            ),
            correlation_id=envelope.correlation_id,
        )
        if not rights.allowed:
            return self._rejected(
                envelope,
                ProviderExecutionErrorCode.RIGHTS_DENIED,
                started,
            )
        material = self._resolve_credential(envelope)
        if material is None:
            return self._rejected(
                envelope,
                ProviderExecutionErrorCode.CREDENTIAL_RESOLUTION_FAILED,
                started,
            )

        request = ProviderTransportRequest(
            provider_id=envelope.provider_id,
            capability=envelope.capability,
            destination=envelope.destination,
            parameters=dict(envelope.request_parameters),
            timeout=envelope.timeout,
        )
        try:
            response = await asyncio.wait_for(
                self.transport.send(request, material),
                timeout=envelope.timeout.total_seconds(),
            )
            material = None
        except TimeoutError:
            material = None
            return self._failed(
                envelope,
                ProviderAttemptOutcome.TIMEOUT,
                ProviderExecutionErrorCode.TIMEOUT,
                started,
            )
        except ProviderTransportRateLimited:
            material = None
            return self._failed(
                envelope,
                ProviderAttemptOutcome.RATE_LIMITED,
                ProviderExecutionErrorCode.RATE_LIMITED,
                started,
            )
        except ProviderTransportFailure:
            material = None
            return self._failed(
                envelope,
                ProviderAttemptOutcome.PROVIDER_FAILURE,
                ProviderExecutionErrorCode.PROVIDER_FAILURE,
                started,
            )
        except Exception:
            material = None
            return self._failed(
                envelope,
                ProviderAttemptOutcome.SYSTEM_FAILURE,
                ProviderExecutionErrorCode.SYSTEM_FAILURE,
                started,
            )

        return self._response_to_result(envelope, response, started)

    def _resolve_credential(
        self,
        envelope: ProviderExecutionEnvelope,
    ) -> SecretMaterial | None:
        if envelope.execution_mode is BillingMode.BYOK:
            if self.byok_secret_service is None or envelope.secret_ref is None:
                return None
            result = self.byok_secret_service.resolve_for_execution(
                WorkerProviderExecutionRequest(
                    account_id=envelope.account_id,
                    provider_id=envelope.provider_id,
                    capability=envelope.capability,
                    secret_ref=envelope.secret_ref,
                    requested_region=envelope.requested_region,
                    requested_data_use=envelope.requested_data_use,
                    requested_execution_mode=envelope.requested_execution_mode,
                    request_metadata={
                        "execution_mode": envelope.execution_mode.value,
                        "adapter_version": PROVIDER_EXECUTION_ADAPTER_VERSION,
                    },
                    verification_reference_id=envelope.verification_request_id,
                ),
                correlation_id=envelope.correlation_id,
            )
            if result.status is not SecretResolutionStatus.SECRET_RESOLVED:
                return None
            self._audit(
                envelope,
                AuditEventType.PROVIDER_SECRET_REFERENCE_VALIDATED,
                [SecretResolutionStatus.SECRET_RESOLVED.value],
            )
            return result.material

        if self.managed_credential_resolver is None or envelope.managed_credential_ref is None:
            return None
        try:
            material = self.managed_credential_resolver.resolve(
                credential_ref=envelope.managed_credential_ref,
                account_id=envelope.account_id,
                provider_id=envelope.provider_id,
            )
        except Exception:
            return None
        self._audit(
            envelope,
            AuditEventType.PROVIDER_SECRET_REFERENCE_VALIDATED,
            ["MANAGED_CREDENTIAL_REFERENCE_VALIDATED"],
        )
        return material

    def _response_to_result(
        self,
        envelope: ProviderExecutionEnvelope,
        response: RawProviderResponse,
        started: float,
    ) -> ProviderExecutionResult:
        if not envelope.destination.validate_source_uri(response.source_uri):
            return self._failed(
                envelope,
                ProviderAttemptOutcome.SYSTEM_FAILURE,
                ProviderExecutionErrorCode.DESTINATION_NOT_ALLOWED,
                started,
            )
        body_size = _body_size(response.body)
        if body_size > self.max_response_bytes:
            return self._failed(
                envelope,
                ProviderAttemptOutcome.PROVIDER_FAILURE,
                ProviderExecutionErrorCode.OVERSIZED_RESPONSE,
                started,
            )
        if response.status_code == 429:
            return self._failed(
                envelope,
                ProviderAttemptOutcome.RATE_LIMITED,
                ProviderExecutionErrorCode.RATE_LIMITED,
                started,
            )
        if response.status_code >= 500:
            return self._failed(
                envelope,
                ProviderAttemptOutcome.PROVIDER_FAILURE,
                ProviderExecutionErrorCode.PROVIDER_FAILURE,
                started,
            )
        if response.status_code < 200 or response.status_code >= 300:
            return self._failed(
                envelope,
                ProviderAttemptOutcome.PROVIDER_FAILURE,
                ProviderExecutionErrorCode.MALFORMED_RESPONSE,
                started,
            )
        if response.content_type not in {"text/plain", "application/json", "text/html"}:
            return self._failed(
                envelope,
                ProviderAttemptOutcome.PROVIDER_FAILURE,
                ProviderExecutionErrorCode.MALFORMED_RESPONSE,
                started,
            )
        payload = ProviderEvidencePayload(
            source_uri=response.source_uri,
            source_class=envelope.source_class,
            content_type=response.content_type,
            body=response.body,
            observed_at=response.observed_at,
            stance=envelope.stance,
            lineage_type=envelope.lineage_type,
            authority_metadata={
                "provider_execution_adapter_version": PROVIDER_EXECUTION_ADAPTER_VERSION,
                "execution_mode": envelope.execution_mode.value,
            },
        )
        result = ProviderExecutionResult(
            provider_id=envelope.provider_id,
            provider_alias=envelope.provider_alias,
            capability=envelope.capability,
            execution_mode=envelope.execution_mode,
            attempt_outcome=ProviderAttemptOutcome.SUCCESS,
            latency_ms=_latency_ms(started),
            evidence=(payload,),
            reason_code=ProviderAttemptOutcome.SUCCESS.value,
            provenance=self._provenance(envelope, ProviderAttemptOutcome.SUCCESS, None),
        )
        self._audit(
            envelope,
            AuditEventType.PROVIDER_EXECUTION_SUCCEEDED,
            [ProviderAttemptOutcome.SUCCESS.value],
        )
        return result

    def _failed(
        self,
        envelope: ProviderExecutionEnvelope,
        outcome: ProviderAttemptOutcome,
        reason: ProviderExecutionErrorCode,
        started: float,
    ) -> ProviderExecutionResult:
        result = ProviderExecutionResult(
            provider_id=envelope.provider_id,
            provider_alias=envelope.provider_alias,
            capability=envelope.capability,
            execution_mode=envelope.execution_mode,
            attempt_outcome=outcome,
            latency_ms=_latency_ms(started),
            evidence=(),
            reason_code=reason.value,
            provenance=self._provenance(envelope, outcome, reason),
        )
        self._audit(
            envelope,
            AuditEventType.PROVIDER_EXECUTION_FAILED,
            [reason.value],
            provider_outcome=outcome.value,
        )
        return result

    def _rejected(
        self,
        envelope: ProviderExecutionEnvelope,
        reason: ProviderExecutionErrorCode,
        started: float,
    ) -> ProviderExecutionResult:
        result = ProviderExecutionResult(
            provider_id=envelope.provider_id,
            provider_alias=envelope.provider_alias,
            capability=envelope.capability,
            execution_mode=envelope.execution_mode,
            attempt_outcome=ProviderAttemptOutcome.SYSTEM_FAILURE,
            latency_ms=_latency_ms(started),
            evidence=(),
            reason_code=reason.value,
            provenance=self._provenance(envelope, ProviderAttemptOutcome.SYSTEM_FAILURE, reason),
        )
        self._audit(
            envelope,
            AuditEventType.PROVIDER_EXECUTION_REJECTED,
            [reason.value],
            provider_outcome=ProviderAttemptOutcome.SYSTEM_FAILURE.value,
        )
        return result

    def _validate_envelope(self, envelope: ProviderExecutionEnvelope) -> None:
        if envelope.timeout.total_seconds() <= 0:
            raise ValueError("timeout must be positive")
        if envelope.execution_mode is BillingMode.BYOK:
            if not envelope.secret_ref or envelope.managed_credential_ref is not None:
                raise ValueError("BYOK execution requires only secret_ref")
        elif envelope.execution_mode is BillingMode.MANAGED:
            if not envelope.managed_credential_ref or envelope.secret_ref is not None:
                raise ValueError("MANAGED execution requires only managed_credential_ref")
        else:
            raise ValueError("unsupported execution mode")
        if envelope.destination.scheme.lower() != "https":
            raise ValueError("provider destination must use https")
        _validate_provider_destination(envelope.destination)
        _validate_request_parameters(envelope.request_parameters)

    def _provenance(
        self,
        envelope: ProviderExecutionEnvelope,
        outcome: ProviderAttemptOutcome,
        reason: ProviderExecutionErrorCode | None,
    ) -> dict[str, object]:
        credential_ref = envelope.secret_ref or envelope.managed_credential_ref or ""
        return {
            "provider_id": str(envelope.provider_id),
            "capability": envelope.capability.value,
            "execution_mode": envelope.execution_mode.value,
            "rights_version": envelope.rights_version,
            "transport_version": PROVIDER_EXECUTION_ADAPTER_VERSION,
            "credential_ref_hash": _safe_ref_hash(credential_ref),
            "credential_ref_version": envelope.credential_ref_version,
            "attempt_outcome": outcome.value,
            "reason_code": reason.value if reason else outcome.value,
        }

    def _audit(
        self,
        envelope: ProviderExecutionEnvelope,
        event_type: AuditEventType,
        reason_codes: list[str],
        *,
        provider_outcome: str | None = None,
    ) -> None:
        if self.audit_service is None:
            return
        credential_ref = envelope.secret_ref or envelope.managed_credential_ref or ""
        payload: dict[str, object] = {
            "provider_id": envelope.provider_id,
            "provider_alias": envelope.provider_alias,
            "capability": envelope.capability.value,
            "billing_mode": envelope.execution_mode.value,
            "execution_mode": envelope.execution_mode.value,
            "rights_version": envelope.rights_version,
            "credential_ref_hash": _safe_ref_hash(credential_ref),
            "credential_version": envelope.credential_ref_version,
            "transport_version": PROVIDER_EXECUTION_ADAPTER_VERSION,
            "reason_codes": reason_codes,
        }
        if provider_outcome is not None:
            payload["provider_outcome"] = provider_outcome
        self.audit_service.append_event(
            account_id=envelope.account_id,
            event_type=event_type,
            correlation_id=envelope.correlation_id,
            request_id=envelope.verification_request_id,
            payload=payload,
        )


@dataclass(frozen=True)
class ProviderExecutorAdapter:
    executor: ProviderExecutor
    provider_alias: str
    execution_mode: BillingMode
    rights_version: str | None
    requested_region: str
    requested_data_use: ProviderDataUse
    requested_execution_mode: ProviderExecutionMode
    destination: ProviderDestination
    request_parameters: Mapping[str, object]
    secret_ref: str | None = None
    managed_credential_ref: str | None = None
    credential_ref_version: str | None = None
    source_class: SourceClass = SourceClass.UNKNOWN
    stance: EvidenceStance = EvidenceStance.UNKNOWN
    lineage_type: EvidenceLineageType = EvidenceLineageType.UNKNOWN
    timeout: timedelta = timedelta(seconds=5)

    async def collect(self, request: EvidenceProviderRequest) -> ProviderEvidenceResult:
        result = await self.executor.execute(
            ProviderExecutionEnvelope(
                account_id=request.account_id,
                verification_request_id=request.verification_request_id,
                provider_id=request.provider_id,
                provider_alias=self.provider_alias,
                capability=request.capability,
                execution_mode=self.execution_mode,
                rights_version=self.rights_version,
                requested_region=self.requested_region,
                requested_data_use=self.requested_data_use,
                requested_execution_mode=self.requested_execution_mode,
                timeout=self.timeout,
                correlation_id=request.verification_request_id,
                destination=self.destination,
                request_parameters=self.request_parameters,
                secret_ref=self.secret_ref,
                managed_credential_ref=self.managed_credential_ref,
                credential_ref_version=self.credential_ref_version,
                source_class=self.source_class,
                stance=self.stance,
                lineage_type=self.lineage_type,
            )
        )
        return ProviderEvidenceResult(
            provider_id=result.provider_id,
            provider_alias=result.provider_alias,
            capability=result.capability,
            attempt_outcome=result.attempt_outcome,
            latency_ms=result.latency_ms,
            evidence=result.evidence,
        )


class FakeProviderTransport:
    def __init__(
        self,
        response: RawProviderResponse | None = None,
        *,
        delay_seconds: float = 0,
        exception: Exception | None = None,
    ) -> None:
        self.response = response
        self.delay_seconds = delay_seconds
        self.exception = exception
        self.calls = 0
        self.credentials_seen: list[str] = []

    async def send(
        self,
        request: ProviderTransportRequest,
        credential_material: SecretMaterial,
    ) -> RawProviderResponse:
        self.calls += 1
        self.credentials_seen.append(credential_material.reveal_for_provider_call())
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)
        if self.exception is not None:
            raise self.exception
        if self.response is None:
            raise ProviderTransportSystemFailure("fake response not configured")
        return self.response


def _credential_mode(execution_mode: BillingMode) -> ProviderCredentialMode:
    if execution_mode is BillingMode.BYOK:
        return ProviderCredentialMode.CUSTOMER_MANAGED
    return ProviderCredentialMode.OUTCOME_MANAGED


def _validate_request_parameters(value: Mapping[str, object]) -> None:
    _validate_mapping(value, depth=0, count=[0])


def _validate_provider_destination(destination: ProviderDestination) -> None:
    hostname = destination.hostname.strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("provider destination hostname is required")
    if hostname in {"localhost", "metadata.google.internal"}:
        raise ValueError("provider destination hostname is not allowed")
    if hostname.endswith(".localhost"):
        raise ValueError("provider destination hostname is not allowed")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise ValueError("provider destination address is not allowed")


def _validate_mapping(value: Mapping[str, object], *, depth: int, count: list[int]) -> None:
    if depth > MAX_REQUEST_PARAMETER_DEPTH:
        raise ValueError("request parameters exceed maximum depth")
    for key, nested in value.items():
        count[0] += 1
        if count[0] > MAX_REQUEST_PARAMETER_COUNT:
            raise ValueError("request parameters exceed maximum count")
        lowered = str(key).lower()
        if lowered in DISALLOWED_PARAMETER_KEYS or "authorization" in lowered:
            raise ValueError("request parameter key is disallowed")
        _validate_parameter_value(nested, depth=depth + 1, count=count)


def _validate_parameter_value(value: object, *, depth: int, count: list[int]) -> None:
    if isinstance(value, str):
        if len(value) > MAX_PARAMETER_STRING_LENGTH:
            raise ValueError("request parameter string is too long")
        return
    if isinstance(value, bool) or isinstance(value, int) or value is None:
        return
    if isinstance(value, Mapping):
        _validate_mapping(value, depth=depth, count=count)
        return
    if isinstance(value, tuple | list):
        for item in value:
            _validate_parameter_value(item, depth=depth, count=count)
        return
    raise ValueError("unsupported request parameter value")


def _body_size(value: bytes | str) -> int:
    if isinstance(value, bytes):
        return len(value)
    return len(value.encode("utf-8"))


def _latency_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


def _safe_ref_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""


__all__ = [
    "FakeProviderTransport",
    "InMemoryManagedCredentialResolver",
    "ManagedCredentialResolver",
    "ProviderDestination",
    "ProviderExecutionEnvelope",
    "ProviderExecutionErrorCode",
    "ProviderExecutionResult",
    "ProviderExecutor",
    "ProviderExecutorAdapter",
    "ProviderTransport",
    "ProviderTransportFailure",
    "ProviderTransportRateLimited",
    "ProviderTransportRequest",
    "ProviderTransportSystemFailure",
    "ProviderTransportTimeout",
    "RawProviderResponse",
]
