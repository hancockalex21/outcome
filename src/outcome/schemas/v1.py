from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from outcome.actions import (
    ACTION_SCHEMA_VERSION,
    ActionBindingContext,
    action_hash,
    material_action_hash,
)
from outcome.domain import (
    AssuranceLevel,
    EscalationStrategy,
    PolicyDecision,
    ProviderHealth,
    VerificationMode,
    VerificationStatus,
)

ReasonCode = Annotated[
    str,
    Field(
        pattern=r"^[A-Z0-9_]+$",
        examples=["POLICY_ALLOWED", "PROVIDER_UNAVAILABLE"],
    ),
]
EvidenceScore = Annotated[float, Field(ge=0.0, le=1.0)]


class OutcomeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Price(OutcomeSchema):
    amount_minor: Annotated[int, Field(ge=0)]
    currency: Annotated[str, Field(min_length=3, max_length=3, examples=["USD"])]


class AuthenticatedIdentityContext(OutcomeSchema):
    account_id: UUID
    agent_id: UUID


class VerifyRequest(OutcomeSchema):
    claim: Annotated[str, Field(min_length=1)]
    subject: Annotated[str, Field(min_length=1)]
    mode: VerificationMode = VerificationMode.INLINE
    requested_assurance: AssuranceLevel = AssuranceLevel.STANDARD
    client_reference_id: Annotated[str | None, Field(min_length=1)] = None


class VerifyResponse(OutcomeSchema):
    request_id: UUID
    identity: AuthenticatedIdentityContext
    status: VerificationStatus
    evidence_score: EvidenceScore | None
    assurance: AssuranceLevel
    receipt_id: UUID | None
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]


class AuthorizeAction(OutcomeSchema):
    action_schema_version: Literal["action.material.v1"] = ACTION_SCHEMA_VERSION
    name: Annotated[str, Field(min_length=1)]
    target: Annotated[str, Field(min_length=1)]
    material: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Persistent, auditable action facts that can affect authorization.",
    )
    ephemeral: dict[str, JsonValue] = Field(
        default_factory=dict,
        description="Transient action context that must not be treated as durable fact.",
    )

    def material_hash(self) -> str:
        return material_action_hash(
            material=self.material,
            action_schema_version=self.action_schema_version,
        )

    def action_hash(self, binding_context: ActionBindingContext) -> str:
        return action_hash(material=self.material, binding_context=binding_context)


class AuthorizeRequest(OutcomeSchema):
    action: AuthorizeAction
    requested_assurance: AssuranceLevel = AssuranceLevel.STANDARD
    verification_receipt_ids: list[UUID] = Field(default_factory=list)
    client_reference_id: Annotated[str | None, Field(min_length=1)] = None


class AuthorizeResponse(OutcomeSchema):
    request_id: UUID
    identity: AuthenticatedIdentityContext
    decision: PolicyDecision
    evidence_score: EvidenceScore | None
    assurance: AssuranceLevel
    receipt_id: UUID | None
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]


class ReceiptResponse(OutcomeSchema):
    request_id: UUID
    identity: AuthenticatedIdentityContext
    receipt_id: UUID
    status: VerificationStatus | None
    decision: PolicyDecision | None
    evidence_score: EvidenceScore | None
    assurance: AssuranceLevel
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]


class Capability(OutcomeSchema):
    name: Annotated[str, Field(min_length=1)]
    status: ProviderHealth
    supported_modes: list[VerificationMode]
    supported_assurance: list[AssuranceLevel]
    escalation_strategies: list[EscalationStrategy]


class CapabilitiesResponse(OutcomeSchema):
    request_id: UUID
    status: Literal["AVAILABLE", "DEGRADED"]
    evidence_score: None = None
    assurance: AssuranceLevel
    receipt_id: None = None
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]
    capabilities: list[Capability]


class PricingItem(OutcomeSchema):
    operation: Literal["verify", "authorize", "receipt", "capabilities", "pricing", "status"]
    assurance: AssuranceLevel
    price: Price


class PricingResponse(OutcomeSchema):
    request_id: UUID
    status: Literal["AVAILABLE"]
    evidence_score: None = None
    assurance: AssuranceLevel
    receipt_id: None = None
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]
    prices: list[PricingItem]


class ComponentStatus(OutcomeSchema):
    name: Annotated[str, Field(min_length=1)]
    health: ProviderHealth


class StatusResponse(OutcomeSchema):
    request_id: UUID
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE"]
    evidence_score: None = None
    assurance: AssuranceLevel
    receipt_id: None = None
    price: Price
    expires_at: datetime
    reason_codes: list[ReasonCode]
    components: list[ComponentStatus]
