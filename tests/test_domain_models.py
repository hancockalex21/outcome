from __future__ import annotations

from enum import StrEnum
from typing import Any

import pytest
from pydantic import BaseModel

from outcome.domain import (
    AssuranceLevel,
    EscalationStrategy,
    PolicyDecision,
    ProviderHealth,
    VerificationMode,
    VerificationStatus,
)


class DomainSnapshot(BaseModel):
    verification_status: VerificationStatus
    policy_decision: PolicyDecision
    verification_mode: VerificationMode
    assurance_level: AssuranceLevel
    provider_health: ProviderHealth
    escalation_strategy: EscalationStrategy


def assert_stable_values(enum_type: type[StrEnum], expected_values: list[str]) -> None:
    assert [member.value for member in enum_type] == expected_values
    assert [str(member) for member in enum_type] == expected_values


def test_domain_enum_values_are_stable() -> None:
    assert_stable_values(
        VerificationStatus,
        [
            "VERIFIED",
            "CONTRADICTED",
            "INCONCLUSIVE",
            "PROVIDER_FAILED",
            "SYSTEM_FAILURE",
        ],
    )
    assert_stable_values(
        PolicyDecision,
        ["ALLOW", "RETRY_HIGHER_ASSURANCE", "ESCALATE", "BLOCK"],
    )
    with pytest.raises(ValueError):
        PolicyDecision("RETRY")
    assert_stable_values(VerificationMode, ["INLINE", "PARALLEL", "ASYNC"])
    assert_stable_values(AssuranceLevel, ["LOW", "STANDARD", "HIGH"])
    assert_stable_values(
        ProviderHealth,
        ["HEALTHY", "DEGRADED", "CIRCUIT_OPEN", "DISABLED"],
    )
    assert_stable_values(
        EscalationStrategy,
        ["FAIL_CLOSED", "RETRY_WITH_BUDGET", "WEBHOOK", "QUEUE"],
    )


def test_domain_model_serialization_values_are_stable() -> None:
    snapshot = DomainSnapshot(
        verification_status=VerificationStatus.PROVIDER_FAILED,
        policy_decision=PolicyDecision.ESCALATE,
        verification_mode=VerificationMode.PARALLEL,
        assurance_level=AssuranceLevel.HIGH,
        provider_health=ProviderHealth.CIRCUIT_OPEN,
        escalation_strategy=EscalationStrategy.RETRY_WITH_BUDGET,
    )

    assert snapshot.model_dump(mode="json") == {
        "verification_status": "PROVIDER_FAILED",
        "policy_decision": "ESCALATE",
        "verification_mode": "PARALLEL",
        "assurance_level": "HIGH",
        "provider_health": "CIRCUIT_OPEN",
        "escalation_strategy": "RETRY_WITH_BUDGET",
    }


def test_operational_failure_statuses_are_distinct_from_contradiction() -> None:
    operational_failures: set[VerificationStatus] = {
        VerificationStatus.PROVIDER_FAILED,
        VerificationStatus.SYSTEM_FAILURE,
    }

    assert VerificationStatus.CONTRADICTED not in operational_failures
    assert {status.value for status in operational_failures} == {
        "PROVIDER_FAILED",
        "SYSTEM_FAILURE",
    }


def test_domain_model_accepts_wire_values() -> None:
    payload: dict[str, Any] = {
        "verification_status": "VERIFIED",
        "policy_decision": "ALLOW",
        "verification_mode": "INLINE",
        "assurance_level": "STANDARD",
        "provider_health": "HEALTHY",
        "escalation_strategy": "FAIL_CLOSED",
    }

    snapshot = DomainSnapshot.model_validate(payload)

    assert snapshot.verification_status is VerificationStatus.VERIFIED
    assert snapshot.model_dump(mode="json") == payload
