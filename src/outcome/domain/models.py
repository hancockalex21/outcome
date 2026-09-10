from __future__ import annotations

from enum import StrEnum


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PROVIDER_FAILED = "PROVIDER_FAILED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    RETRY = "RETRY"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class VerificationMode(StrEnum):
    INLINE = "INLINE"
    PARALLEL = "PARALLEL"
    ASYNC = "ASYNC"


class AssuranceLevel(StrEnum):
    LOW = "LOW"
    STANDARD = "STANDARD"
    HIGH = "HIGH"


class ProviderHealth(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    DISABLED = "DISABLED"


class EscalationStrategy(StrEnum):
    FAIL_CLOSED = "FAIL_CLOSED"
    RETRY_WITH_BUDGET = "RETRY_WITH_BUDGET"
    WEBHOOK = "WEBHOOK"
    QUEUE = "QUEUE"
