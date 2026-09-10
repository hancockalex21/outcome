from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from outcome.auth import (
    AgentApiKey,
    AgentApiKeyAuthenticator,
    ApiKeyAuthError,
    ApiKeyScope,
    redact_authorization_header,
)
from outcome.auth.api_keys import extract_key_prefix, verify_api_key
from outcome.db.metadata import metadata
from outcome.db.models import Account, AgentCredential, AuditEvent


def build_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    session.add(Account(id=uuid4(), display_name="Test Account", status="active"))
    session.commit()
    return session


def account_id_from_session(session: Session) -> object:
    return session.scalar(select(Account.id))


def create_key(
    session: Session,
    *,
    scopes: set[ApiKeyScope] | None = None,
) -> tuple[AgentApiKeyAuthenticator, str, AgentCredential]:
    account_id = account_id_from_session(session)
    assert account_id is not None

    authenticator = AgentApiKeyAuthenticator(session)
    result = authenticator.create_development_key(
        account_id=account_id,
        agent_id=uuid4(),
        scopes=scopes or {ApiKeyScope.VERIFY_WRITE},
    )
    session.commit()
    return authenticator, result.plaintext_key, result.credential


def test_valid_key_authenticates_and_updates_last_used_at() -> None:
    session = build_session()
    authenticator, plaintext_key, credential = create_key(session)

    assert credential.last_used_at is None

    principal = authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}",
        required_scope=ApiKeyScope.VERIFY_WRITE,
        account_id=credential.account_id,
    )
    session.commit()

    assert isinstance(principal, AgentApiKey)
    assert principal.account_id == credential.account_id
    assert credential.last_used_at is not None


def test_invalid_key_is_rejected() -> None:
    session = build_session()
    authenticator, plaintext_key, _credential = create_key(session)

    assert authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}wrong",
        required_scope=ApiKeyScope.VERIFY_WRITE,
    ) is ApiKeyAuthError.INVALID


def test_malformed_key_is_rejected() -> None:
    session = build_session()
    authenticator = AgentApiKeyAuthenticator(session)

    assert authenticator.authenticate(
        authorization_header="Basic not-a-bearer-token",
        required_scope=ApiKeyScope.VERIFY_WRITE,
    ) is ApiKeyAuthError.MALFORMED
    assert authenticator.authenticate(
        authorization_header="Bearer not-outcome-format",
        required_scope=ApiKeyScope.VERIFY_WRITE,
    ) is ApiKeyAuthError.MALFORMED


def test_revoked_key_is_rejected() -> None:
    session = build_session()
    authenticator, plaintext_key, credential = create_key(session)
    authenticator.revoke(credential)
    session.commit()

    assert authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}",
        required_scope=ApiKeyScope.VERIFY_WRITE,
    ) is ApiKeyAuthError.REVOKED


def test_missing_scope_is_rejected() -> None:
    session = build_session()
    authenticator, plaintext_key, _credential = create_key(
        session,
        scopes={ApiKeyScope.RECEIPTS_READ},
    )

    assert authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}",
        required_scope=ApiKeyScope.AUTHORIZE_WRITE,
    ) is ApiKeyAuthError.MISSING_SCOPE


def test_cross_tenant_access_attempt_is_rejected() -> None:
    session = build_session()
    authenticator, plaintext_key, _credential = create_key(session)

    assert authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}",
        required_scope=ApiKeyScope.VERIFY_WRITE,
        account_id=uuid4(),
    ) is ApiKeyAuthError.WRONG_ACCOUNT


def test_plaintext_key_is_not_persisted() -> None:
    session = build_session()
    _authenticator, plaintext_key, credential = create_key(session)

    session.expire_all()
    persisted = session.get(AgentCredential, credential.id)
    assert persisted is not None
    assert persisted.key_hash != plaintext_key
    assert persisted.key_fingerprint != plaintext_key
    assert persisted.key_ciphertext_ref is None
    assert plaintext_key not in repr(persisted.__dict__)

    key_prefix = extract_key_prefix(plaintext_key)
    assert key_prefix == persisted.key_prefix
    assert verify_api_key(plaintext_key, persisted.key_hash)


def test_authorization_header_is_redacted_from_logs() -> None:
    headers = {
        "Authorization": "Bearer oc_agent_prefix_secret",
        "content-type": "application/json",
    }

    assert redact_authorization_header(headers) == {
        "Authorization": "[REDACTED]",
        "content-type": "application/json",
    }


def test_last_used_at_update_does_not_touch_audit_events() -> None:
    session = build_session()
    authenticator, plaintext_key, credential = create_key(session)

    result = authenticator.authenticate(
        authorization_header=f"Bearer {plaintext_key}",
        required_scope=ApiKeyScope.VERIFY_WRITE,
        account_id=credential.account_id,
    )
    session.commit()

    assert isinstance(result, AgentApiKey)
    assert credential.last_used_at is not None
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0
