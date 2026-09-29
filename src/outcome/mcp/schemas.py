from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

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
    authorization: AuthorizationHeader | None = Field(
        default=None,
        description=(
            "Existing Outcome Authorization header for stdio clients. Remote HTTP MCP clients "
            "must send this as the HTTP Authorization header instead."
        ),
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
    policy_id: UUID | None = Field(
        default=None,
        description="Explicit tenant policy. Omit with policy_version for fail-closed resolution.",
    )
    policy_version: Annotated[int | None, Field(ge=1)] = None
    action: AuthorizeAction
    requested_assurance: AssuranceLevel = AssuranceLevel.STANDARD
    authorization_expires_at: datetime
    verification_required: bool = True
    verification_result_id: UUID | None = None
    verification_claim: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    verification_subject: Annotated[str | None, Field(min_length=1, max_length=4096)] = None
    client_reference_id: Annotated[str | None, Field(min_length=1, max_length=255)] = None

    @model_validator(mode="after")
    def validate_linked_fields(self) -> MCPAuthorizeRequest:
        if (self.policy_id is None) != (self.policy_version is None):
            raise ValueError("policy_id and policy_version must be supplied together")
        claim_fields = (self.verification_claim, self.verification_subject)
        if (claim_fields[0] is None) != (claim_fields[1] is None):
            raise ValueError(
                "verification_claim and verification_subject must be supplied together"
            )
        if self.verification_result_id is not None and claim_fields[0] is not None:
            raise ValueError("use either verification_result_id or a verification claim, not both")
        if (
            self.verification_required
            and self.verification_result_id is None
            and claim_fields[0] is None
        ):
            raise ValueError("verification requires verification_result_id or claim and subject")
        return self


class MCPConsumeReceiptRequest(MCPAuthenticatedRequest):
    execution_request_id: UUID
    signed_receipt: dict[str, JsonValue]
    action_schema_version: str
    material_action: dict[str, JsonValue]


class MCPConsumeReceiptData(MCPSchema):
    status: str
    executable: bool
    consumption_id: UUID | None
    receipt_id: UUID | None
    authorization_request_id: UUID | None
    action_hash: str | None
    execution_request_id: UUID
    validation_status: str | None
    reason_code: str


class MCPErrorCode(str):
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
    VALIDATION_FAILED = "VALIDATION_FAILED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    POLICY_BLOCK = "POLICY_BLOCK"
    NO_APPLICABLE_POLICY = "NO_APPLICABLE_POLICY"
    AMBIGUOUS_POLICY = "AMBIGUOUS_POLICY"
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
    policy_id: UUID
    policy_version: int
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
    data: MCPVerifyData | MCPAuthorizeData | MCPConsumeReceiptData | dict[str, JsonValue] | None = (
        None
    )


class OutcomeCapabilities(MCPSchema):
    service_name: Literal["Outcome"] = "Outcome"
    service_version: str = OUTCOME_SERVICE_VERSION
    mcp_adapter_version: Literal["outcome-mcp-v1"] = "outcome-mcp-v1"
    supported_tools: tuple[str, ...] = (
        "outcome_verify",
        "outcome_authorize",
        "outcome_execute_authorized",
    )
    verification_modes: tuple[str, ...] = tuple(mode.value for mode in VerificationMode)
    assurance_levels: tuple[str, ...] = tuple(level.value for level in AssuranceLevel)
    policy_decisions: tuple[str, ...] = tuple(decision.value for decision in PolicyDecision)
    action_schema_version: str = ACTION_SCHEMA_VERSION
    authentication: Literal["Authorization: Bearer oc_agent_*"] = "Authorization: Bearer oc_agent_*"
    receipt_support: bool = True
    receipt_version: str = "outcome.authorization.receipt.v1"
    execution_validation: Literal["server-boundary-with-one-time-consumption"] = (
        "server-boundary-with-one-time-consumption"
    )
    billing_model: str = "prepaid integer micro-USD; Postgres ledger is authoritative"
    evidence_score_description: str = (
        "0-10000 deterministic evidence-strength score; not a calibrated probability"
    )
    purpose: str = "Verify bounded claims and authorize one exact material action before execution."
    workflow: tuple[str, ...] = (
        "Call outcome_verify when only a claim decision is needed.",
        "Call outcome_authorize before an external, financial, or otherwise material action.",
        "Provide policy_id plus policy_version, or omit both for tenant-local "
        "fail-closed resolution.",
        "For required verification, provide an existing verification_result_id or "
        "provide verification_claim plus verification_subject for internal verification.",
        "An ALLOW receipt authorizes only the exact bound action and never executes it.",
        "Optionally call outcome_execute_authorized at the execution boundary to validate "
        "and consume the receipt once; that tool still does not execute the action.",
    )
    policy_resolution: str = (
        "Explicit selection is supported. Automatic selection considers only currently "
        "effective published policies in the authenticated tenant; zero or multiple "
        "applicable policies fail closed."
    )
    verification_security: str = (
        "Clients cannot assert verification status or score. Result IDs are tenant checked; "
        "claim-based authorization uses Outcome's VerificationOrchestrator."
    )
    decision_recovery: dict[str, str] = {
        "ALLOW": "Use the signed receipt only for the exact action before expiry.",
        "BLOCK": (
            "Do not execute; correct the action or policy/evidence issue before a new request."
        ),
        "RETRY_HIGHER_ASSURANCE": (
            "Submit a new request at the required higher assurance with a new idempotency key."
        ),
        "ESCALATE": "Do not execute; route to the account's configured human or review process.",
    }
    receipt_does_not_execute: Literal[True] = True
    billing_behavior: str = (
        "Authorization uses prepaid micro-USD credit. Idempotent replay does not create a "
        "second charge; insufficient funds fail closed."
    )
