from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol, cast
from uuid import UUID, uuid4

from mcp.server import MCPServer
from pydantic import JsonValue
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.auth import AgentApiKey, AgentApiKeyAuthenticator, ApiKeyAuthError, ApiKeyScope
from outcome.authorization import (
    AuthenticatedAuthorizationContext,
    AuthorizationIdempotencyConflict,
    AuthorizationMaterial,
    AuthorizationOrchestrationError,
    AuthorizationOrchestrationResult,
    AuthorizationOrchestrator,
    AuthorizationRequestEnvelope,
    CrossTenantAuthorizationAccess,
)
from outcome.pricing import CapabilityName
from outcome.verification import (
    AuthenticatedVerificationContext,
    CrossTenantVerificationAccess,
    VerificationIdempotencyConflict,
    VerificationMaterial,
    VerificationOrchestrationError,
    VerificationOrchestrationResult,
    VerificationOrchestrator,
    VerificationRequestEnvelope,
)

from .schemas import (
    MCP_ADAPTER_VERSION,
    OUTCOME_SERVICE_VERSION,
    MCPAuthorizeData,
    MCPAuthorizeRequest,
    MCPToolResponse,
    MCPVerifyData,
    MCPVerifyRequest,
    OutcomeCapabilities,
)

MCP_SERVER_NAME = "Outcome"
MCP_SERVER_DESCRIPTION = (
    "Secure Outcome verification and authorization adapter for autonomous agents."
)
TOOL_OUTCOME_VERIFY = "outcome_verify"
TOOL_OUTCOME_AUTHORIZE = "outcome_authorize"
TOOL_OUTCOME_CAPABILITIES = "outcome_capabilities"


class OutcomeMCPApplication(Protocol):
    async def verify(
        self,
        *,
        identity: AgentApiKey,
        request: MCPVerifyRequest,
        correlation_id: UUID,
    ) -> VerificationOrchestrationResult:
        raise NotImplementedError

    async def authorize(
        self,
        *,
        identity: AgentApiKey,
        request: MCPAuthorizeRequest,
        correlation_id: UUID,
    ) -> AuthorizationOrchestrationResult:
        raise NotImplementedError


@dataclass(frozen=True)
class OutcomeMCPDependencies:
    session_factory: Callable[[], Session]
    application_factory: Callable[[Session], OutcomeMCPApplication]


class OutcomeMCPService:
    def __init__(self, dependencies: OutcomeMCPDependencies) -> None:
        self.dependencies = dependencies

    async def verify(self, request: MCPVerifyRequest) -> MCPToolResponse:
        return await self._run_tool(
            tool_name=TOOL_OUTCOME_VERIFY,
            required_scope=ApiKeyScope.VERIFY_WRITE,
            authorization=request.authorization,
            call=lambda session, identity, correlation_id: self.dependencies.application_factory(
                session
            ).verify(identity=identity, request=request, correlation_id=correlation_id),
        )

    async def authorize(self, request: MCPAuthorizeRequest) -> MCPToolResponse:
        return await self._run_tool(
            tool_name=TOOL_OUTCOME_AUTHORIZE,
            required_scope=ApiKeyScope.AUTHORIZE_WRITE,
            authorization=request.authorization,
            call=lambda session, identity, correlation_id: self.dependencies.application_factory(
                session
            ).authorize(identity=identity, request=request, correlation_id=correlation_id),
        )

    async def _run_tool(
        self,
        *,
        tool_name: str,
        required_scope: ApiKeyScope,
        authorization: str,
        call: Callable[[Session, AgentApiKey, UUID], object],
    ) -> MCPToolResponse:
        started = time.monotonic()
        correlation_id = uuid4()
        session = self.dependencies.session_factory()
        try:
            auth = AgentApiKeyAuthenticator(session).authenticate(
                authorization_header=authorization,
                required_scope=required_scope,
            )
            if isinstance(auth, ApiKeyAuthError):
                _audit_mcp(
                    session=session,
                    account_id=None,
                    tool_name=tool_name,
                    event_type=AuditEventType.MCP_TOOL_REJECTED,
                    correlation_id=correlation_id,
                    reason_codes=[_auth_error_code(auth)],
                    started=started,
                )
                return _error_response(_auth_error_code(auth))
            _audit_mcp(
                session=session,
                account_id=auth.account_id,
                tool_name=tool_name,
                event_type=AuditEventType.MCP_TOOL_INVOKED,
                correlation_id=correlation_id,
                reason_codes=["MCP_TOOL_INVOKED"],
                started=started,
                credential_id=auth.credential_id,
            )
            result = await call(session, auth, correlation_id)  # type: ignore[misc]
            response = _success_response(result)
            _audit_mcp(
                session=session,
                account_id=auth.account_id,
                tool_name=tool_name,
                event_type=AuditEventType.MCP_TOOL_COMPLETED,
                correlation_id=correlation_id,
                reason_codes=response.reason_codes or ("MCP_TOOL_COMPLETED",),
                started=started,
                credential_id=auth.credential_id,
            )
            session.commit()
            return response
        except (AuthorizationIdempotencyConflict, VerificationIdempotencyConflict):
            session.rollback()
            return _error_response("IDEMPOTENCY_CONFLICT")
        except (
            AuthorizationOrchestrationError,
            VerificationOrchestrationError,
            CrossTenantAuthorizationAccess,
            CrossTenantVerificationAccess,
        ):
            session.rollback()
            return _error_response("SYSTEM_FAILURE")
        except Exception:
            session.rollback()
            return _error_response("SYSTEM_FAILURE")
        finally:
            session.close()


class OutcomeApplicationServices:
    def __init__(
        self,
        *,
        verification_orchestrator: VerificationOrchestrator,
        authorization_orchestrator: AuthorizationOrchestrator,
    ) -> None:
        self.verification_orchestrator = verification_orchestrator
        self.authorization_orchestrator = authorization_orchestrator

    async def verify(
        self,
        *,
        identity: AgentApiKey,
        request: MCPVerifyRequest,
        correlation_id: UUID,
    ) -> VerificationOrchestrationResult:
        return await self.verification_orchestrator.verify_async(
            VerificationRequestEnvelope(
                authenticated=AuthenticatedVerificationContext(
                    account_id=identity.account_id,
                    agent_id=identity.agent_id,
                ),
                material=VerificationMaterial(
                    capability=CapabilityName.VERIFY,
                    mode=request.mode,
                    assurance=request.requested_assurance,
                    claim={"claim": request.claim},
                    subject={"subject": request.subject},
                    provider_ids=(),
                ),
                idempotency_key=request.idempotency_key,
                correlation_id=correlation_id,
                ephemeral=request.ephemeral,
            ),
            providers=(),
        )

    async def authorize(
        self,
        *,
        identity: AgentApiKey,
        request: MCPAuthorizeRequest,
        correlation_id: UUID,
    ) -> AuthorizationOrchestrationResult:
        return await self.authorization_orchestrator.authorize_async(
            AuthorizationRequestEnvelope(
                authenticated=AuthenticatedAuthorizationContext(
                    account_id=identity.account_id,
                    agent_id=identity.agent_id,
                ),
                material=AuthorizationMaterial(
                    policy_id=request.policy_id,
                    policy_version=request.policy_version,
                material_action=request.action.material,
                    action_schema_version=request.action.action_schema_version,
                    assurance_level=request.requested_assurance,
                    authorization_expires_at=request.authorization_expires_at,
                    verification_required=request.verification_required,
                    verification_result_id=request.verification_result_id,
                ),
                idempotency_key=request.idempotency_key,
                correlation_id=correlation_id,
                ephemeral=request.action.ephemeral,
            )
        )


def create_mcp_server(dependencies: OutcomeMCPDependencies) -> MCPServer:
    service = OutcomeMCPService(dependencies)
    server = MCPServer(
        MCP_SERVER_NAME,
        title="Outcome",
        description=MCP_SERVER_DESCRIPTION,
        version=OUTCOME_SERVICE_VERSION,
        instructions=(
            "Use outcome_verify for verification and outcome_authorize for authorization. "
            "Authenticate with an existing Outcome API key."
        ),
    )

    @server.tool(
        name=TOOL_OUTCOME_VERIFY,
        description=(
            "Verify a bounded claim using existing Outcome verification services. "
            "Evidence Score is an internal 0-10000 strength score, not a probability."
        ),
        structured_output=True,
    )
    async def outcome_verify(request: MCPVerifyRequest) -> dict[str, object]:
        return (await service.verify(request)).model_dump(mode="json")

    @server.tool(
        name=TOOL_OUTCOME_AUTHORIZE,
        description=(
            "Authorize one exact material action through existing Outcome policy, "
            "billing, action binding, and receipt services."
        ),
        structured_output=True,
    )
    async def outcome_authorize(request: MCPAuthorizeRequest) -> dict[str, object]:
        return (await service.authorize(request)).model_dump(mode="json")

    @server.tool(
        name=TOOL_OUTCOME_CAPABILITIES,
        description="Return safe machine-readable Outcome MCP capability metadata.",
        structured_output=True,
    )
    def outcome_capabilities() -> dict[str, object]:
        return OutcomeCapabilities().model_dump(mode="json")

    @server.resource(
        "outcome://capabilities",
        name="outcome_capabilities",
        description="Safe machine-readable Outcome capability discovery document.",
        mime_type="application/json",
    )
    def outcome_capabilities_resource() -> str:
        return OutcomeCapabilities().model_dump_json(indent=2)

    return server


def _success_response(result: object) -> MCPToolResponse:
    if isinstance(result, VerificationOrchestrationResult):
        score = result.evidence_score.final_score if result.evidence_score else None
        return MCPToolResponse(
            ok=True,
            reason_codes=tuple(result.reason_codes),
            data=MCPVerifyData(
                verification_request_id=result.verification_request_id,
                verification_result_id=result.verification_result_id,
                status=result.status,
                evidence_score_basis_points=score,
                evidence_score_version=result.scoring_version,
                reason_codes=tuple(result.reason_codes),
                evidence_ids_used=result.evidence_ids_used,
                evidence_ids_excluded=result.evidence_ids_excluded,
                providers_contributed=result.providers_contributed,
                providers_failed=result.providers_failed,
                idempotent_replay=result.idempotent_replay,
            ),
        )
    if isinstance(result, AuthorizationOrchestrationResult):
        return MCPToolResponse(
            ok=True,
            reason_codes=tuple(result.reason_codes),
            data=MCPAuthorizeData(
                authorization_request_id=result.authorization_request_id,
                authorization_result_id=result.authorization_result_id,
                decision=result.decision,
                action_hash=result.action_hash,
                material_hash=result.material_hash,
                receipt_id=result.receipt_id,
                signed_receipt=(
                    cast(dict[str, JsonValue], result.signed_receipt.to_public_dict())
                    if result.signed_receipt
                    else None
                ),
                expires_at=result.expires_at,
                reason_codes=tuple(result.reason_codes),
                verification_result_id=result.verification_result_id,
                evidence_score_basis_points=result.evidence_score_basis_points,
                billing=cast(
                    dict[str, JsonValue] | None,
                    _json_mapping(result.provenance.get("billing")),
                ),
                idempotent_replay=result.idempotent_replay,
            ),
        )
    return _error_response("SYSTEM_FAILURE")


def _error_response(code: str) -> MCPToolResponse:
    return MCPToolResponse(ok=False, error_code=code, reason_codes=(code,), data=None)


def _auth_error_code(error: ApiKeyAuthError) -> str:
    if error is ApiKeyAuthError.MISSING_SCOPE:
        return "INSUFFICIENT_SCOPE"
    return "AUTHENTICATION_FAILED"


def _audit_mcp(
    *,
    session: Session,
    account_id: UUID | None,
    tool_name: str,
    event_type: AuditEventType,
    correlation_id: UUID,
    reason_codes: tuple[str, ...] | list[str],
    started: float,
    credential_id: UUID | None = None,
) -> None:
    if account_id is None:
        return
    AuditService(session).append_event(
        account_id=account_id,
        event_type=event_type,
        correlation_id=correlation_id,
        payload={
            "agent_credential_id": credential_id,
            "mcp_tool_name": tool_name,
            "mcp_tool_version": MCP_ADAPTER_VERSION,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "reason_codes": list(reason_codes),
        },
    )


def _json_mapping(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    return {str(key): item for key, item in value.items()}


__all__ = [
    "MCP_ADAPTER_VERSION",
    "MCP_SERVER_NAME",
    "OutcomeApplicationServices",
    "OutcomeMCPApplication",
    "OutcomeMCPDependencies",
    "OutcomeMCPService",
    "create_mcp_server",
]
