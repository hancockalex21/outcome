from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import (
    AuditEventType,
    AuditPayloadRejected,
    AuditService,
    CrossTenantAuditAccess,
)
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.db.models import Account, AuditEvent
from outcome.domain import PolicyDecision, ProviderHealth, VerificationStatus
from tests.test_api_keys import build_session


def create_account(session: Session) -> UUID:
    account_id = uuid4()
    session.add(Account(id=account_id, display_name="Second Account", status="active"))
    session.commit()
    return account_id


def test_append_event() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    correlation_id = uuid4()
    request_id = uuid4()

    event = AuditService(session).append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=correlation_id,
        request_id=request_id,
        payload={"reason_codes": ["REQUEST_ACCEPTED"]},
    )
    session.commit()

    assert event.account_id == account_id
    assert event.correlation_id == correlation_id
    assert event.request_id == request_id
    assert event.event_type is AuditEventType.REQUEST_ACCEPTED
    assert event.payload["reason_codes"] == ["REQUEST_ACCEPTED"]


def test_ordered_timeline_reconstruction() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    correlation_id = uuid4()
    service = AuditService(session)

    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=correlation_id,
    )
    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.POLICY_SELECTED,
        correlation_id=correlation_id,
    )
    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.DECISION_MADE,
        correlation_id=correlation_id,
        payload={"policy_decision": PolicyDecision.ALLOW},
    )
    session.commit()

    timeline = service.timeline_for_correlation(
        account_id=account_id,
        correlation_id=correlation_id,
    )

    assert [event.event_type for event in timeline] == [
        AuditEventType.REQUEST_ACCEPTED,
        AuditEventType.POLICY_SELECTED,
        AuditEventType.DECISION_MADE,
    ]


def test_multiple_event_types_in_one_lifecycle() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    correlation_id = uuid4()
    service = AuditService(session)

    for event_type in AuditEventType:
        service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload={
                "provider_alias": "search-provider",
                "provider_health": ProviderHealth.HEALTHY,
                "verification_status": VerificationStatus.VERIFIED,
                "policy_decision": PolicyDecision.ALLOW,
                "reason_codes": [event_type.value.upper()],
            }
            if event_type
            in {
                AuditEventType.PROVIDER_ATTEMPTED,
                AuditEventType.EVIDENCE_ACCEPTED,
                AuditEventType.SCORE_COMPUTED,
                AuditEventType.DECISION_MADE,
                AuditEventType.PROVIDER_FAILURE,
            }
            else {},
        )
    session.commit()

    timeline = service.timeline_for_correlation(
        account_id=account_id,
        correlation_id=correlation_id,
    )

    assert len(timeline) == len(AuditEventType)
    assert {event.event_type for event in timeline} == set(AuditEventType)


def test_cross_tenant_access_denied() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    other_account_id = create_account(session)
    correlation_id = uuid4()

    service = AuditService(session)
    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=correlation_id,
    )
    session.commit()

    with pytest.raises(CrossTenantAuditAccess):
        service.timeline_for_correlation(
            account_id=other_account_id,
            correlation_id=correlation_id,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("Authorization", "Bearer oc_agent_prefix_secret"),
        ("api_key", "oc_agent_prefix_secret"),
        ("cookie", "session=value"),
        ("stripe_signature", "sig"),
        ("raw_byok_credentials", {"secret": "value"}),
        ("decrypted_provider_secret", "secret"),
        ("raw_html", "<html>secret</html>"),
        ("raw_evidence", "full evidence body"),
        ("external_response", {"full": "payload"}),
    ],
)
def test_sensitive_field_rejected(field: str, value: object) -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None

    with pytest.raises(AuditPayloadRejected):
        AuditService(session).append_event(
            account_id=account_id,
            event_type=AuditEventType.EVIDENCE_REJECTED,
            correlation_id=uuid4(),
            payload={field: value},
        )

    assert session.scalar(select(AuditEvent)) is None


def test_authorization_and_api_key_secret_never_persisted() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    auth_result = AgentApiKeyAuthenticator(session).create_development_key(
        account_id=account_id,
        agent_id=uuid4(),
        scopes={ApiKeyScope.VERIFY_WRITE},
    )
    plaintext_key = auth_result.plaintext_key

    AuditService(session).append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=uuid4(),
        payload={
            "agent_credential_id": auth_result.credential.id,
            "agent_key_prefix": auth_result.credential.key_prefix,
        },
    )
    session.commit()

    event = session.scalar(select(AuditEvent))
    assert event is not None
    assert plaintext_key not in repr(event.payload)
    assert "Authorization" not in event.payload
    assert event.payload["agent_key_prefix"] == auth_result.credential.key_prefix


def test_raw_evidence_and_html_not_persisted() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    service = AuditService(session)

    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.EVIDENCE_ACCEPTED,
        correlation_id=uuid4(),
        payload={
            "evidence_ref": "object://evidence/123",
            "evidence_hash": "sha256:abc",
            "evidence_type": "web_snapshot",
        },
    )
    session.commit()

    event = session.scalar(select(AuditEvent))
    assert event is not None
    assert "raw_html" not in event.payload
    assert "raw_evidence" not in event.payload
    assert event.payload["evidence_ref"] == "object://evidence/123"


def test_historical_audit_event_cannot_be_modified_through_service() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    service = AuditService(session)
    correlation_id = uuid4()

    first_event = service.append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=correlation_id,
    )
    session.commit()

    assert not hasattr(service, "update_event")
    assert not hasattr(service, "delete_event")

    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.TIMEOUT,
        correlation_id=correlation_id,
    )
    session.commit()

    persisted = session.get(AuditEvent, first_event.id)
    assert persisted is not None
    assert persisted.event_type == AuditEventType.REQUEST_ACCEPTED.value


def test_correlation_id_behavior() -> None:
    session = build_session()
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    included_correlation_id = uuid4()
    excluded_correlation_id = uuid4()
    service = AuditService(session)

    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=included_correlation_id,
    )
    service.append_event(
        account_id=account_id,
        event_type=AuditEventType.REQUEST_ACCEPTED,
        correlation_id=excluded_correlation_id,
    )
    session.commit()

    timeline = service.timeline_for_correlation(
        account_id=account_id,
        correlation_id=included_correlation_id,
    )

    assert len(timeline) == 1
    assert timeline[0].correlation_id == included_correlation_id
    assert timeline[0].payload["correlation_id"] == str(included_correlation_id)
