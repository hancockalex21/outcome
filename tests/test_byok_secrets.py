from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditService
from outcome.db.models import (
    Account,
    AuditEvent,
    CustomerProviderCredential,
    Provider,
    ProviderRight,
)
from outcome.domain import ProviderHealth
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderRightsService,
    ProviderRightsStatus,
)
from outcome.secrets import CredentialLifecycleState, CredentialType, SecretReference
from outcome.worker.secrets import (
    DevelopmentSecretResolver,
    InMemoryDevelopmentSecretStore,
    SecretMaterial,
    SecretResolutionStatus,
    WorkerProviderExecutionRequest,
    WorkerSecretResolutionService,
)
from tests.test_api_keys import build_session

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
PROVIDER_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
OTHER_PROVIDER_ID = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
SECRET_REF = "sec_ref_dev_001"
PLAINTEXT_SECRET = "provider-secret-value-never-log"
NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)


def setup_session() -> Session:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.add(
        Provider(
            id=PROVIDER_ID,
            account_id=ACCOUNT_ID,
            name="BYOK Provider",
            health=ProviderHealth.HEALTHY.value,
            config={},
        )
    )
    session.add(
        Provider(
            id=OTHER_PROVIDER_ID,
            account_id=ACCOUNT_ID,
            name="Other Provider",
            health=ProviderHealth.HEALTHY.value,
            config={},
        )
    )
    session.commit()
    return session


def add_byok_rights(session: Session, *, allowed: bool = True) -> None:
    session.add(
        ProviderRight(
            id=uuid4(),
            account_id=ACCOUNT_ID,
            provider_id=PROVIDER_ID,
            right_name="byok-provider:verify:BYOK:v1",
            provider_alias="byok-provider",
            capability=CapabilityName.VERIFY.value,
            billing_mode=BillingMode.BYOK.value,
            enabled=True,
            rights_status=(
                ProviderRightsStatus.AUTHORIZED.value
                if allowed
                else ProviderRightsStatus.UNKNOWN.value
            ),
            permitted_regions=["US"],
            permitted_data_use=[ProviderDataUse.CLAIM_VERIFICATION.value],
            permitted_execution_modes=[ProviderExecutionMode.INLINE.value],
            customer_secret_required=True,
            outcome_managed_credential_allowed=False,
            customer_managed_credential_allowed=True,
            evidence_retention_allowed=False,
            caching_allowed=False,
            commercial_usage_allowed=True,
            automated_agent_usage_allowed=True,
            rights_version="rights-byok-v1",
            effective_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1),
            reason_code="RIGHTS_ACTIVE",
            tenant_restrictions={},
            constraints={},
        )
    )
    session.commit()


def add_credential(
    session: Session,
    *,
    account_id: UUID = ACCOUNT_ID,
    provider_id: UUID = PROVIDER_ID,
    secret_ref: str = SECRET_REF,
    lifecycle_state: CredentialLifecycleState = CredentialLifecycleState.ACTIVE,
) -> CustomerProviderCredential:
    credential = CustomerProviderCredential(
        id=uuid4(),
        account_id=account_id,
        provider_id=provider_id,
        secret_ref=secret_ref,
        credential_type=CredentialType.API_KEY.value,
        lifecycle_state=lifecycle_state.value,
        version="cred-v1",
        external_secret_locator="dev-store://sec_ref_dev_001",
        metadata_json={"label": "dev credential"},
        rotated_at=NOW if lifecycle_state is CredentialLifecycleState.ROTATED else None,
        disabled_at=NOW if lifecycle_state is CredentialLifecycleState.DISABLED else None,
        revoked_at=NOW if lifecycle_state is CredentialLifecycleState.REVOKED else None,
    )
    session.add(credential)
    session.commit()
    return credential


def execution_request(
    *,
    account_id: UUID = ACCOUNT_ID,
    provider_id: UUID = PROVIDER_ID,
    secret_ref: str = SECRET_REF,
) -> WorkerProviderExecutionRequest:
    return WorkerProviderExecutionRequest(
        account_id=account_id,
        provider_id=provider_id,
        capability=CapabilityName.VERIFY,
        secret_ref=secret_ref,
        requested_region="US",
        requested_data_use=ProviderDataUse.CLAIM_VERIFICATION,
        requested_execution_mode=ProviderExecutionMode.INLINE,
        request_metadata={"request_id": "safe-request-ref"},
        action_reference_id=uuid4(),
        verification_reference_id=uuid4(),
        evaluated_at=NOW,
    )


def resolution_service(
    session: Session,
    store: InMemoryDevelopmentSecretStore,
) -> WorkerSecretResolutionService:
    return WorkerSecretResolutionService(
        session,
        resolver=DevelopmentSecretResolver(store=store, session=session),
        provider_rights_service=ProviderRightsService(session, AuditService(session)),
        audit_service=AuditService(session),
    )


def test_api_control_plane_reference_uses_opaque_secret_ref_only() -> None:
    reference = SecretReference(
        secret_ref=SECRET_REF,
        account_id=ACCOUNT_ID,
        provider_id=PROVIDER_ID,
        credential_type=CredentialType.API_KEY,
        created_at=NOW,
        lifecycle_state=CredentialLifecycleState.ACTIVE,
        version="cred-v1",
        metadata={"label": "safe"},
    )

    assert reference.secret_ref == SECRET_REF
    assert PLAINTEXT_SECRET not in repr(reference)


def test_valid_active_secret_resolves_in_worker() -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.put(secret_ref=SECRET_REF, secret_value=PLAINTEXT_SECRET)

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.SECRET_RESOLVED
    assert result.material is not None
    assert result.material.reveal_for_provider_call() == PLAINTEXT_SECRET


def test_cross_tenant_resolution_denied() -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.put(secret_ref=SECRET_REF, secret_value=PLAINTEXT_SECRET)

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(account_id=OTHER_ACCOUNT_ID),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.TENANT_MISMATCH


def test_wrong_provider_denied() -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.put(secret_ref=SECRET_REF, secret_value=PLAINTEXT_SECRET)

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(provider_id=OTHER_PROVIDER_ID),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.PROVIDER_MISMATCH


@pytest.mark.parametrize(
    ("state", "status"),
    [
        (CredentialLifecycleState.REVOKED, SecretResolutionStatus.SECRET_REVOKED),
        (CredentialLifecycleState.DISABLED, SecretResolutionStatus.SECRET_DISABLED),
        (CredentialLifecycleState.ROTATED, SecretResolutionStatus.SECRET_REVOKED),
    ],
)
def test_inactive_secret_states_fail_closed(
    state: CredentialLifecycleState,
    status: SecretResolutionStatus,
) -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session, lifecycle_state=state)
    store = InMemoryDevelopmentSecretStore()
    store.put(secret_ref=SECRET_REF, secret_value=PLAINTEXT_SECRET)

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )

    assert result.status is status
    assert result.material is None


def test_missing_secret_denied() -> None:
    session = setup_session()
    add_byok_rights(session)
    store = InMemoryDevelopmentSecretStore()

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.SECRET_NOT_FOUND


def test_rights_denial_occurs_before_secret_resolution() -> None:
    session = setup_session()
    add_byok_rights(session, allowed=False)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.fail_reads = True

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.RIGHTS_DENIED


def test_secret_material_redacts_repr_and_str_and_json() -> None:
    material = SecretMaterial(PLAINTEXT_SECRET, credential_type=CredentialType.API_KEY)

    assert PLAINTEXT_SECRET not in repr(material)
    assert PLAINTEXT_SECRET not in str(material)
    with pytest.raises(TypeError):
        json.dumps(material)


def test_plaintext_secret_never_appears_in_audit_or_db() -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.put(secret_ref=SECRET_REF, secret_value=PLAINTEXT_SECRET)

    resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )
    session.commit()

    persisted = session.scalars(select(CustomerProviderCredential)).all()
    events = session.scalars(select(AuditEvent)).all()
    assert persisted
    assert events
    assert PLAINTEXT_SECRET not in repr([row.__dict__ for row in persisted])
    assert PLAINTEXT_SECRET not in repr([event.payload for event in events])


def test_internal_execution_envelope_contains_reference_not_secret_value() -> None:
    envelope = execution_request()

    envelope_dict = asdict(envelope)

    assert envelope_dict["secret_ref"] == SECRET_REF
    assert PLAINTEXT_SECRET not in repr(envelope_dict)


def test_secret_store_failure_fails_closed() -> None:
    session = setup_session()
    add_byok_rights(session)
    add_credential(session)
    store = InMemoryDevelopmentSecretStore()
    store.fail_reads = True

    result = resolution_service(session, store).resolve_for_execution(
        execution_request(),
        correlation_id=uuid4(),
    )

    assert result.status is SecretResolutionStatus.SECRET_STORE_FAILURE
