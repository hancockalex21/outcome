import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ValidationError
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from outcome.actions import ACTION_SCHEMA_VERSION
from outcome.audit import AuditService
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.authorization import AuthorizationOrchestrator
from outcome.billing import AuthorizationBillingService
from outcome.db.metadata import metadata
from outcome.db.models import Account, Receipt
from outcome.domain import AssuranceLevel, PolicyDecision, VerificationStatus
from outcome.execution import (
    ExecutionAuthorizationRequest,
    ExecutionAuthorizationValidator,
    ReceiptConsumptionService,
)
from outcome.ledger import LedgerService
from outcome.mcp import create_mcp_server
from outcome.mcp.schemas import MCP_ADAPTER_VERSION, MCPAuthorizeRequest
from outcome.mcp.server import OutcomeApplicationServices, OutcomeMCPDependencies
from outcome.policies import PolicyEvaluationService
from outcome.pricing import (
    BillingMode,
    CapabilityName,
    CapabilityPricingConfig,
    InMemoryPricingConfigStore,
    PricingService,
)
from outcome.receipts import ReceiptService
from outcome.reservations import ReservationService
from outcome.verification import VerificationOrchestrator
from tests.test_authorization_orchestrator import (
    ACCOUNT_ID,
    AGENT_ID,
    POLICY_ID,
    add_policy,
    add_verification_result,
    material_action,
)
from tests.test_receipt_service import signer, verifier

NOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)
SECOND_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
SECOND_AGENT_ID = UUID("33333333-3333-4333-8333-333333333333")


@pytest.fixture()
def redis_client() -> Redis:
    client = Redis(host="127.0.0.1", port=6379, db=12)
    try:
        client.ping()
    except RedisError:
        pytest.skip("local Redis is not available")
    client.flushdb()
    yield client
    client.flushdb()


def build_session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Account(id=ACCOUNT_ID, display_name="MCP", status="active"))
    session.commit()
    return session


def make_key(
    session: Session,
    *scopes: ApiKeyScope,
    account_id: UUID = ACCOUNT_ID,
    agent_id: UUID = AGENT_ID,
) -> str:
    result = AgentApiKeyAuthenticator(session).create_development_key(
        account_id=account_id,
        agent_id=agent_id,
        scopes=set(scopes),
    )
    session.commit()
    return result.plaintext_key


def mcp_server(session: Session, redis_client: Redis):
    def app_factory(factory_session: Session) -> OutcomeApplicationServices:
        audit = AuditService(factory_session)
        ledger = LedgerService(factory_session, audit)
        pricing = PricingService(
            config_store=InMemoryPricingConfigStore(
                (
                    CapabilityPricingConfig(
                        capability=CapabilityName.AUTHORIZE,
                        billing_mode=BillingMode.MANAGED,
                        pricing_config_version="mcp-test-pricing-v1",
                        minimum_price_micro_usd=1_000_000,
                        included_evidence_budget_micro_usd=0,
                        expected_compute_cost_micro_usd=500_000,
                        expected_managed_supplier_cost_micro_usd=0,
                        target_gross_margin_bps=0,
                        maximum_retry_budget_micro_usd=0,
                        maximum_total_cost_micro_usd=1_000_000,
                        enabled=True,
                    ),
                )
            ),
            audit_service=audit,
        )
        receipt_service = ReceiptService(
            factory_session,
            signer=signer(),
            verifier=verifier(),
            audit_service=audit,
        )
        reservation_service = ReservationService(
            redis=redis_client,
            ledger_service=ledger,
            audit_service=audit,
        )
        billing = AuthorizationBillingService(
            factory_session,
            pricing_service=pricing,
            reservation_service=reservation_service,
            ledger_service=ledger,
            audit_service=audit,
            clock=lambda: NOW,
        )
        execution_validator = ExecutionAuthorizationValidator(
            receipt_verifier=verifier(),
            audit_service=audit,
        )
        return OutcomeApplicationServices(
            verification_orchestrator=VerificationOrchestrator(
                factory_session,
                audit_service=audit,
                clock=lambda: NOW,
            ),
            authorization_orchestrator=AuthorizationOrchestrator(
                factory_session,
                policy_service=PolicyEvaluationService(
                    factory_session,
                    audit,
                    clock=lambda: NOW,
                ),
                receipt_service=receipt_service,
                execution_validator=execution_validator,
                billing_service=billing,
                audit_service=audit,
                clock=lambda: NOW,
            ),
            receipt_consumption_service=ReceiptConsumptionService(
                factory_session,
                validator=execution_validator,
                audit_service=audit,
            ),
        )

    return create_mcp_server(
        OutcomeMCPDependencies(
            session_factory=lambda: session,
            application_factory=app_factory,
        )
    )


def fund_account(session: Session, amount: int = 5_000_000) -> None:
    LedgerService(session).fund_account(
        account_id=ACCOUNT_ID,
        amount_micro_usd=amount,
        idempotency_key=f"fund:{uuid4()}",
        correlation_id=uuid4(),
    )
    session.commit()


def authorize_request(authorization: str, verification_result_id: UUID) -> dict[str, object]:
    return {
        "authorization": authorization,
        "idempotency_key": "mcp-authorize-key",
        "policy_id": str(POLICY_ID),
        "policy_version": 1,
        "requested_assurance": AssuranceLevel.STANDARD.value,
        "authorization_expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "verification_required": True,
        "verification_result_id": str(verification_result_id),
        "action": {
            "action_schema_version": ACTION_SCHEMA_VERSION,
            "name": "purchase",
            "target": "merchant-a",
            "material": material_action(amount=1_000_000),
            "ephemeral": {"trace_id": str(uuid4()), "nonce": "abc"},
        },
    }


@pytest.mark.asyncio
async def test_mcp_tool_discovery_and_schema(redis_client: Redis) -> None:
    session = build_session()
    async with Client(mcp_server(session, redis_client)) as client:
        tools = await client.list_tools()
    by_name = {tool.name: tool for tool in tools.tools}

    assert set(by_name) == {
        "outcome_verify",
        "outcome_authorize",
        "outcome_capabilities",
        "outcome_execute_authorized",
    }
    assert by_name["outcome_verify"].description
    assert by_name["outcome_authorize"].description
    assert "request" in by_name["outcome_verify"].input_schema["properties"]
    assert "request" in by_name["outcome_authorize"].input_schema["properties"]
    async with Client(mcp_server(session, redis_client)) as client:
        capabilities = await client.call_tool("outcome_capabilities", {})
    assert (
        PolicyDecision.RETRY_HIGHER_ASSURANCE.value
        in capabilities.structured_content["policy_decisions"]
    )


@pytest.mark.asyncio
async def test_mcp_verify_authenticated_invocation(redis_client: Redis) -> None:
    session = build_session()
    key = make_key(session, ApiKeyScope.VERIFY_WRITE)

    async with Client(mcp_server(session, redis_client)) as client:
        result = await client.call_tool(
            "outcome_verify",
            {
                "request": {
                    "authorization": f"Bearer {key}",
                    "idempotency_key": "verify-key",
                    "claim": "merchant exists",
                    "subject": "merchant-a",
                }
            },
        )

    response = result.structured_content
    assert response["ok"] is True
    assert response["data"]["status"] in {
        VerificationStatus.PROVIDER_FAILED.value,
        VerificationStatus.INCONCLUSIVE.value,
        VerificationStatus.VERIFIED.value,
        VerificationStatus.CONTRADICTED.value,
    }
    assert response["data"]["evidence_score_basis_points"] is None or isinstance(
        response["data"]["evidence_score_basis_points"],
        int,
    )


@pytest.mark.asyncio
async def test_remote_mcp_uses_http_authorization_header(redis_client: Redis) -> None:
    session = build_session()
    key = make_key(session, ApiKeyScope.VERIFY_WRITE)
    app = mcp_server(session, redis_client).streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        max_request_body_size=1_048_576,
        transport_security=TransportSecuritySettings(allowed_hosts=["localhost"]),
    )
    transport = httpx2.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://localhost",
            headers={"Authorization": f"Bearer {key}"},
        ) as http_client:
            async with Client(
                streamable_http_client("http://localhost/mcp", http_client=http_client)
            ) as client:
                tools = await client.list_tools()
                result = await client.call_tool(
                    "outcome_verify",
                    {
                        "request": {
                            "idempotency_key": "remote-verify-key",
                            "claim": "merchant exists",
                            "subject": "merchant-a",
                        }
                    },
                )

    assert {tool.name for tool in tools.tools} >= {"outcome_verify", "outcome_authorize"}
    assert result.structured_content["ok"] is True


@pytest.mark.asyncio
async def test_remote_mcp_two_tenant_context_does_not_bleed(redis_client: Redis) -> None:
    session = build_session()
    session.add(Account(id=SECOND_ACCOUNT_ID, display_name="MCP B", status="active"))
    session.commit()
    key_a = make_key(session, ApiKeyScope.VERIFY_WRITE)
    key_b = make_key(
        session,
        ApiKeyScope.VERIFY_WRITE,
        account_id=SECOND_ACCOUNT_ID,
        agent_id=SECOND_AGENT_ID,
    )
    app = mcp_server(session, redis_client).streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        max_request_body_size=1_048_576,
        transport_security=TransportSecuritySettings(allowed_hosts=["localhost"]),
    )

    async def call_verify(key: str, idempotency_key: str) -> dict[str, object]:
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url="http://localhost",
            headers={"Authorization": f"Bearer {key}"},
        ) as http_client:
            async with Client(
                streamable_http_client("http://localhost/mcp", http_client=http_client)
            ) as client:
                result = await client.call_tool(
                    "outcome_verify",
                    {
                        "request": {
                            "idempotency_key": idempotency_key,
                            "claim": "merchant exists",
                            "subject": "merchant-a",
                        }
                    },
                )
                return result.structured_content

    async with app.router.lifespan_context(app):
        result_a, result_b = await asyncio.gather(
            call_verify(key_a, "tenant-a-verify"),
            call_verify(key_b, "tenant-b-verify"),
        )

    assert result_a["ok"] is True
    assert result_b["ok"] is True
    assert (
        result_a["data"]["verification_request_id"] != result_b["data"]["verification_request_id"]
    )


@pytest.mark.asyncio
async def test_agent_style_authorize_returns_signed_receipt(redis_client: Redis) -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(
        session,
        status=VerificationStatus.VERIFIED,
        score=8_500,
    )
    fund_account(session)
    key = make_key(session, ApiKeyScope.AUTHORIZE_WRITE)

    async with Client(mcp_server(session, redis_client)) as client:
        result = await client.call_tool(
            "outcome_authorize",
            {"request": authorize_request(f"Bearer {key}", verification_result_id)},
        )

    response = result.structured_content
    assert response["ok"] is True
    assert response["data"]["decision"] == PolicyDecision.ALLOW.value
    assert response["data"]["receipt_id"] is not None
    assert response["data"]["signed_receipt"] is not None
    assert response["data"]["billing"]["actual_charge_micro_usd"] == 1_000_000
    signed = ReceiptService(session, signer=signer(), verifier=verifier()).get(
        account_id=ACCOUNT_ID,
        receipt_id=UUID(response["data"]["receipt_id"]),
    )
    assert signed is not None
    execution = ExecutionAuthorizationValidator(receipt_verifier=verifier()).validate(
        ExecutionAuthorizationRequest(
            signed_receipt=signed,
            proposed_material=material_action(amount=1_000_000),
            proposed_action_schema_version=ACTION_SCHEMA_VERSION,
            authenticated_account_id=ACCOUNT_ID,
            current_timestamp=NOW,
        ),
        correlation_id=uuid4(),
    )
    assert execution.executable is True


@pytest.mark.asyncio
async def test_mcp_authorize_replay_reuses_receipt_and_billing(redis_client: Redis) -> None:
    session = build_session()
    add_policy(session)
    verification_result_id = add_verification_result(session)
    fund_account(session)
    key = make_key(session, ApiKeyScope.AUTHORIZE_WRITE)
    request = authorize_request(f"Bearer {key}", verification_result_id)

    async with Client(mcp_server(session, redis_client)) as client:
        first = await client.call_tool("outcome_authorize", {"request": request})
        second = await client.call_tool("outcome_authorize", {"request": request})

    assert (
        first.structured_content["data"]["receipt_id"]
        == second.structured_content["data"]["receipt_id"]
    )
    assert second.structured_content["data"]["idempotent_replay"] is True
    assert len(session.scalars(select(Receipt)).all()) == 1


@pytest.mark.asyncio
async def test_mcp_security_failures_are_sanitized(redis_client: Redis) -> None:
    session = build_session()
    verify_only_key = make_key(session, ApiKeyScope.VERIFY_WRITE)
    authorize_only_key = make_key(session, ApiKeyScope.AUTHORIZE_WRITE)
    revoked = AgentApiKeyAuthenticator(session).create_development_key(
        account_id=ACCOUNT_ID,
        agent_id=AGENT_ID,
        scopes={ApiKeyScope.AUTHORIZE_WRITE},
    )
    AgentApiKeyAuthenticator(session).revoke(revoked.credential)
    session.commit()

    async with Client(mcp_server(session, redis_client)) as client:
        missing = await client.call_tool(
            "outcome_authorize",
            {
                "request": authorize_request(
                    "Bearer missing",
                    add_verification_result(session),
                )
            },
        )
        malformed = await client.call_tool(
            "outcome_authorize",
            {
                "request": authorize_request(
                    "not bearer",
                    add_verification_result(session, status=VerificationStatus.VERIFIED),
                )
            },
        )
        insufficient = await client.call_tool(
            "outcome_authorize",
            {
                "request": authorize_request(
                    f"Bearer {verify_only_key}",
                    add_verification_result(session, status=VerificationStatus.VERIFIED),
                )
            },
        )
        revoked_result = await client.call_tool(
            "outcome_authorize",
            {
                "request": authorize_request(
                    f"Bearer {revoked.plaintext_key}",
                    add_verification_result(session, status=VerificationStatus.VERIFIED),
                )
            },
        )
        verify_scope = await client.call_tool(
            "outcome_verify",
            {
                "request": {
                    "authorization": f"Bearer {authorize_only_key}",
                    "idempotency_key": "bad-scope",
                    "claim": "x",
                    "subject": "y",
                }
            },
        )

    assert missing.structured_content["error_code"] == "AUTHENTICATION_FAILED"
    assert malformed.structured_content["error_code"] == "AUTHENTICATION_FAILED"
    assert revoked_result.structured_content["error_code"] == "AUTHENTICATION_FAILED"
    assert insufficient.structured_content["error_code"] == "INSUFFICIENT_SCOPE"
    assert verify_scope.structured_content["error_code"] == "INSUFFICIENT_SCOPE"
    assert "oc_agent" not in json.dumps(
        [
            missing.structured_content,
            malformed.structured_content,
            insufficient.structured_content,
            revoked_result.structured_content,
            verify_scope.structured_content,
        ]
    )


def test_mcp_request_schema_rejects_extra_account_override() -> None:
    key = "Bearer oc_agent_fake_fake"
    with pytest.raises(ValidationError):
        MCPAuthorizeRequest.model_validate(
            {
                **authorize_request(key, uuid4()),
                "account_id": str(UUID("22222222-2222-4222-8222-222222222222")),
            }
        )


def test_discovery_document_is_safe_and_accurate() -> None:
    document = json.loads(Path("docs/discovery/outcome-capabilities.json").read_text())
    assert document["service_name"] == "Outcome"
    assert document["mcp_adapter_version"] == MCP_ADAPTER_VERSION
    assert document["policy_decisions"] == [
        "ALLOW",
        "RETRY_HIGHER_ASSURANCE",
        "ESCALATE",
        "BLOCK",
    ]
    forbidden = json.dumps(document).lower()
    assert "x402" in forbidden
    assert "provider_secret" not in forbidden
    assert "api_key" not in forbidden
    assert document["evidence_score"]["not_a_probability"] is True


@pytest.mark.asyncio
async def test_mcp_does_not_expose_dangerous_tools(redis_client: Redis) -> None:
    session = build_session()
    async with Client(mcp_server(session, redis_client)) as client:
        tools = await client.list_tools()
    tool_names = {tool.name for tool in tools.tools}
    assert "provider_execute" not in tool_names
    assert "secret_resolve" not in tool_names
    assert "ledger_mutate" not in tool_names
    assert "http_fetch" not in tool_names
