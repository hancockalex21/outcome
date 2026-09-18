from __future__ import annotations

import json
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from outcome.actions import (
    ACTION_SCHEMA_VERSION,
    ActionBindingContext,
    CanonicalizationError,
    action_hash,
    canonical_material_json,
)
from outcome.audit import (
    AuditEventType,
    AuditPayloadRejected,
    AuditService,
)
from outcome.auth import AgentApiKeyAuthenticator, ApiKeyScope
from outcome.db.models import AuditEvent
from outcome.pricing import BillingMode
from outcome.providers import ProviderAttemptOutcome
from outcome.receipts import (
    ReceiptVerificationStatus,
    SignedReceipt,
)
from outcome.worker import (
    FakeProviderTransport,
    ProviderDestination,
    ProviderExecutionErrorCode,
    ProviderTransportFailure,
)
from tests.test_api_keys import account_id_from_session, create_key
from tests.test_api_keys import build_session as build_auth_session
from tests.test_provider_execution import (
    BYOK_SECRET,
    add_credential,
    add_right,
    byok_executor,
    envelope,
    response,
    setup_session,
)
from tests.test_receipt_consumption import (
    EXPIRES_AT,
    authorization_request,
    consume,
    signed_receipt,
)
from tests.test_receipt_service import verifier

NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "destination",
    [
        ProviderDestination(scheme="https", hostname="localhost"),
        ProviderDestination(scheme="https", hostname="service.localhost"),
        ProviderDestination(scheme="https", hostname="127.0.0.1"),
        ProviderDestination(scheme="https", hostname="10.0.0.1"),
        ProviderDestination(scheme="https", hostname="172.16.0.1"),
        ProviderDestination(scheme="https", hostname="192.168.1.1"),
        ProviderDestination(scheme="https", hostname="169.254.169.254"),
        ProviderDestination(scheme="https", hostname="::1"),
        ProviderDestination(scheme="https", hostname="metadata.google.internal"),
    ],
)
async def test_provider_executor_rejects_local_private_and_metadata_destinations(
    destination: ProviderDestination,
) -> None:
    session = setup_session()
    transport = FakeProviderTransport(response())

    result = await byok_executor(session, transport).execute(
        envelope(destination=destination)
    )

    assert result.attempt_outcome is ProviderAttemptOutcome.SYSTEM_FAILURE
    assert result.reason_code == ProviderExecutionErrorCode.INVALID_ENVELOPE.value
    assert transport.calls == 0


@pytest.mark.asyncio
async def test_provider_transport_exception_cannot_exfiltrate_secret_to_result_or_audit() -> None:
    session = setup_session()
    add_right(session, billing_mode=BillingMode.BYOK)
    add_credential(session)
    transport = FakeProviderTransport(
        exception=ProviderTransportFailure(f"upstream leaked {BYOK_SECRET}")
    )

    result = await byok_executor(session, transport).execute(envelope())

    assert result.attempt_outcome is ProviderAttemptOutcome.PROVIDER_FAILURE
    serialized = repr(result) + json.dumps(result.provenance, sort_keys=True)
    audit_repr = repr(session.scalars(select(AuditEvent)).all())
    assert BYOK_SECRET not in serialized
    assert BYOK_SECRET not in audit_repr


@pytest.mark.parametrize(
    "payload",
    [
        {"amount": 1.2},
        {"amount": float("nan")},
        {"amount": 9_007_199_254_740_992},
        {"nested": [{"too": {"large": 9_007_199_254_740_992}}]},
    ],
)
def test_action_canonicalization_rejects_ambiguous_or_unsafe_values(
    payload: dict[str, object],
) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_material_json(material=payload)


def test_action_canonicalization_distinguishes_material_ambiguity_cases() -> None:
    base = {"merchant": "Cafe", "amount": 100, "currency": "USD"}
    reordered = {"currency": "USD", "amount": 100, "merchant": "Cafe"}
    null_field = {"merchant": "Cafe", "amount": 100, "currency": "USD", "memo": None}
    array_a = {"items": ["sku-1", "sku-2"]}
    array_b = {"items": ["sku-2", "sku-1"]}
    unicode_a = {"merchant": "Cafe\u0301"}
    unicode_b = {"merchant": "Caf\u00e9"}

    assert canonical_material_json(material=base) == canonical_material_json(
        material=reordered
    )
    assert canonical_material_json(material=base) != canonical_material_json(
        material=null_field
    )
    assert canonical_material_json(material=array_a) != canonical_material_json(
        material=array_b
    )
    assert canonical_material_json(material=unicode_a) != canonical_material_json(
        material=unicode_b
    )


def test_action_hash_binds_account_policy_schema_and_expiry_under_fuzzed_key_order() -> None:
    rng = random.Random(30)
    material = {
        "merchant": "merchant-a",
        "amount": 100,
        "currency": "USD",
        "destination": "merchant-a",
        "sku": "sku-1",
    }
    context = ActionBindingContext(
        account_id=uuid4(),
        policy_version="1",
        action_schema_version=ACTION_SCHEMA_VERSION,
        authorization_expires_at=NOW,
    )
    hashes: set[str] = set()
    items = list(material.items())
    for _ in range(25):
        rng.shuffle(items)
        hashes.add(action_hash(material=dict(items), binding_context=context))

    assert len(hashes) == 1
    assert action_hash(material=material, binding_context=context) != action_hash(
        material=material,
        binding_context=replace(context, policy_version="2"),
    )
    assert action_hash(material=material, binding_context=context) == action_hash(
        material=material,
        binding_context=replace(
            context,
            authorization_expires_at=NOW.astimezone(timezone(timedelta(hours=-5))),
        ),
    )
    assert action_hash(material=material, binding_context=context) != action_hash(
        material=material,
        binding_context=replace(
            context,
            authorization_expires_at=NOW + timedelta(seconds=1),
        ),
    )


def test_receipt_tampering_unknown_key_and_replay_after_consumption_fail_closed() -> None:
    receipt = signed_receipt()
    tampered = SignedReceipt(
        payload=replace(receipt.payload, action_hash="0" * 64),
        signature=receipt.signature,
    )
    unknown_key = SignedReceipt(
        payload=replace(receipt.payload, signing_key_id="unknown-key"),
        signature=receipt.signature,
    )

    assert (
        verifier().verify(tampered, now=NOW).status
        is ReceiptVerificationStatus.SIGNATURE_INVALID
    )
    assert (
        verifier().verify(unknown_key, now=NOW).status
        is ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY
    )

    session = build_auth_session()
    first = consume(
        session,
        request=authorization_request(receipt=receipt),
    )
    second = consume(
        session,
        request=authorization_request(receipt=receipt),
        execution_request_id=uuid4(),
    )

    assert first.status.name == "CONSUMED"
    assert second.status.name == "ALREADY_CONSUMED"


def test_expired_receipt_signature_can_be_valid_but_not_executable() -> None:
    receipt = signed_receipt(expires_at=EXPIRES_AT)

    result = verifier().verify(receipt, now=EXPIRES_AT + timedelta(seconds=1))

    assert result.status is ReceiptVerificationStatus.RECEIPT_EXPIRED
    assert result.signature_valid is True
    assert result.currently_executable is False


def test_audit_rejects_sensitive_and_unrecognized_payload_fields() -> None:
    session = build_auth_session()
    audit = AuditService(session)
    account_id = account_id_from_session(session)
    assert account_id is not None

    with pytest.raises(AuditPayloadRejected):
        audit.append_event(
            account_id=account_id,
            event_type=AuditEventType.REQUEST_ACCEPTED,
            correlation_id=uuid4(),
            payload={"authorization_header": "Bearer oc_agent_secret"},
        )
    with pytest.raises(AuditPayloadRejected):
        audit.append_event(
            account_id=account_id,
            event_type=AuditEventType.REQUEST_ACCEPTED,
            correlation_id=uuid4(),
            payload={"raw_provider_body": "unsafe"},
        )


def test_api_key_secret_is_one_time_and_not_in_repr_after_creation() -> None:
    session = build_auth_session()
    _authenticator, key, credential = create_key(session)

    assert key.startswith("oc_agent_")
    assert key not in repr(credential)
    assert key not in repr(session.get(type(credential), credential.id))


def test_malformed_and_very_long_api_keys_fail_without_prefix_scan_or_secret_leakage() -> None:
    session = build_auth_session()
    create_key(session)
    authenticator = AgentApiKeyAuthenticator(session)
    huge = "Bearer oc_agent_" + ("x" * 20_000)

    result = authenticator.authenticate(
        authorization_header=huge,
        required_scope=ApiKeyScope.VERIFY_WRITE,
    )

    assert result.name in {"MALFORMED", "INVALID"}
    assert "x" * 128 not in repr(session.scalars(select(AuditEvent)).all())


def test_receipt_private_material_never_appears_in_public_receipt() -> None:
    secret_private_material = "PRIVATE_SIGNING_KEY_SENTINEL"
    receipt = signed_receipt()

    public = json.dumps(receipt.to_public_dict(), sort_keys=True)

    assert secret_private_material not in public
    assert "private_key" not in public
    assert receipt.payload.signing_key_id in public


def test_provider_response_source_uri_must_match_configured_destination() -> None:
    destination = ProviderDestination(scheme="https", hostname="provider.example")
    assert destination.validate_source_uri("https://provider.example/evidence")
    assert not destination.validate_source_uri("https://evil.example/evidence")
    assert not destination.validate_source_uri("http://provider.example/evidence")
