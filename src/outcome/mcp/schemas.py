from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationMode, VerificationStatus
from outcome.schemas.v1 import AuthorizeAction

OUTCOME_SERVICE_VERSION = "0.1.0"
MCP_ADAPTER_VERSION = "outcome-mcp-v1"

AuthorizationHeader = Annotated[str, Field(min_length=1, max_length=512)]
IdempotencyKey = Annotated[str, Field(min_length=1, max_length=255)]
ReasonCode = Annotated[str, Field(pattern=r"^[A-Z0-9_]+$")]


class MCPSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MCPAuthenticatedRequest(MCPSchema):
    authorization: AuthorizationHeader = Field(
        description="Existing Outcome Authorization header: Bearer oc_agent_..."
    )


class MCPVerifyRequest(MCPAuthenticatedRequest):
    idempotency_key: IdempotencyKey
    claim: Annotated[str, Field(min_length=1, max_length=4096)]
    subject: Annotated[str, Field(min_length=1, max_length=4096)]
    mode: VerificationMode = VerificationMode.INLINE
    requested_assurance: AssuranceLevel = AssuranceLevel.STANDARD
    client_reference_id: Annotated[str | None, Field(min_length=1, max_length=255)] = None
    ephemeral: dict[str, JsonValue] = Field(default_factory=dict)


class MCPAuthorizeRequest(MCPAuthenticatedRequest):
    idempotency_key: IdempotencyKey
    policy_id: UUID
    policy_version: Annotated[int, Field(ge=1)]
    action: AuthorizeAction
    requested_assurance: AssuranceLevel = AssuranceLevel.STANDARD
    authorization_expires_at: datetime
    verification_required: bool = True
    verification_result_id: UUID | None = None
    client_reference_id: Annotated[str | None, Field(min_length=1, max_length=255)] = None


class MCPErrorCode(str):
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    POLICY_BLOCK = "POLICY_BLOCK"
    RETRY_HIGHER_ASSURANCE = "RETRY_HIGHER_ASSURANCE"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"
    SYSTEM_FAILURE = "SYSTEM_FAILURE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class MCPVerifyData(MCPSchema):
    verification_request_id: UUID
    verification_result_id: UUID | None
    status: VerificationStatus
    evidence_score_basis_points: Annotated[int | None, Field(ge=0, le=10000)]
    evidence_score_version: str | None
    reason_codes: tuple[ReasonCode, ...]
    evidence_ids_used: tuple[UUID, ...]
    evidence_ids_excluded: tuple[UUID, ...]
    providers_contributed: tuple[UUID, ...]
    providers_failed: tuple[UUID, ...]
    idempotent_replay: bool


class MCPAuthorizeData(MCPSchema):
    authorization_request_id: UUID
    authorization_result_id: UUID | None
    decision: PolicyDecision
    action_hash: str | None
    material_hash: str
    receipt_id: UUID | None
    signed_receipt: dict[str, JsonValue] | None
    expires_at: datetime
    reason_codes: tuple[ReasonCode, ...]
    verification_result_id: UUID | None
    evidence_score_basis_points: Annotated[int | None, Field(ge=0, le=10000)]
    billing: dict[str, JsonValue] | None
    idempotent_replay: bool


class MCPToolResponse(MCPSchema):
    ok: bool
    tool_version: Literal["outcome-mcp-v1"] = "outcome-mcp-v1"
    error_code: str | None = None
    reason_codes: tuple[ReasonCode, ...] = ()
    data: MCPVerifyData | MCPAuthorizeData | dict[str, JsonValue] | None = None


class OutcomeCapabilities(MCPSchema):
    service_name: Literal["Outcome"] = "Outcome"
    service_version: str = OUTCOME_SERVICE_VERSION
    mcp_adapter_version: Literal["outcome-mcp-v1"] = "outcome-mcp-v1"
    supported_tools: tuple[Literal["outcome_verify", "outcome_authorize"], ...] = (
        "outcome_verify",
        "outcome_authorize",
    )
    verification_modes: tuple[str, ...] = tuple(mode.value for mode in VerificationMode)
    assurance_levels: tuple[str, ...] = tuple(level.value for level in AssuranceLevel)
    policy_decisions: tuple[str, ...] = tuple(decision.value for decision in PolicyDecision)
    action_schema_version: str = ACTION_SCHEMA_VERSION
    authentication: Literal["Authorization: Bearer oc_agent_*"] = (
        "Authorization: Bearer oc_agent_*"
    )
    receipt_support: bool = True
    billing_model: str = "prepaid integer micro-USD; Postgres ledger is authoritative"
    evidence_score_description: str = (
        "0-10000 deterministic evidence-strength score; not a calibrated probability"
    )
