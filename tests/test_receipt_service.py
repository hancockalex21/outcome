from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from outcome.actions import CanonicalizationError
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Account, Receipt
from outcome.domain import PolicyDecision, VerificationStatus
from outcome.receipts import (
    RECEIPT_VERSION,
    CrossTenantReceiptAccess,
    Ed25519ReceiptSigner,
    Ed25519ReceiptVerifier,
    ReceiptPayload,
    ReceiptService,
    ReceiptVerificationStatus,
    SignedReceipt,
    canonical_receipt_json,
)
from tests.test_api_keys import build_session

PRIVATE_KEY_BYTES = bytes(range(32))
PRIVATE_KEY_B64 = base64.urlsafe_b64encode(PRIVATE_KEY_BYTES).decode("ascii")
SIGNING_KEY_ID = "receipt-test-key-2026-09"
RECEIPT_ID = UUID("33333333-3333-4333-8333-333333333333")
ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
AUTHORIZATION_REQUEST_ID = UUID("44444444-4444-4444-8444-444444444444")
AUTHORIZATION_RESULT_ID = UUID("55555555-5555-4555-8555-555555555555")
ISSUED_AT = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=UTC)
EXPIRES_AT = datetime(2026, 9, 10, 12, 5, 0, 123456, tzinfo=UTC)
ACTION_HASH = "0dec498922c309d952bd398ec020c25e3ce037c5bb9972fad2e41232e90b09df"
EXPECTED_CANONICAL_RECEIPT = (
    '{"account_id":"11111111-1111-4111-8111-111111111111",'
    '"action_hash":"0dec498922c309d952bd398ec020c25e3ce037c5bb9972fad2e41232e90b09df",'
    '"action_schema_version":"action.material.v1",'
    '"authorization_request_id":"44444444-4444-4444-8444-444444444444",'
    '"expires_at":"2026-09-10T12:05:00.123456Z",'
    '"issued_at":"2026-09-10T12:00:00.123456Z",'
    '"policy_decision":"ALLOW","policy_version":"policy-v1",'
    '"receipt_id":"33333333-3333-4333-8333-333333333333",'
    '"receipt_version":"outcome.authorization.receipt.v1",'
    '"signing_key_id":"receipt-test-key-2026-09",'
    '"verification_status":"VERIFIED"}'
)
EXPECTED_CANONICAL_RECEIPT_SHA256 = (
    "02de6b2882e334af89552d4d916f97692ee5be50e59fc7602f651ae12a92f5c6"
)
EXPECTED_SIGNATURE = (
    "xrfTr-VKywA0bBkjmlpQDxAXfk7-LzVHrAnetiZ2maKN-I0T6j2Z2e_uCmi9-XNSEaPZhlLkICv3I9XzttvmBg=="
)


def signer() -> Ed25519ReceiptSigner:
    return Ed25519ReceiptSigner.from_private_key_bytes(
        signing_key_id=SIGNING_KEY_ID,
        private_key_bytes=PRIVATE_KEY_BYTES,
    )


def verifier() -> Ed25519ReceiptVerifier:
    receipt_signer = signer()
    return Ed25519ReceiptVerifier({SIGNING_KEY_ID: receipt_signer.public_key_bytes()})


def payload(
    *,
    account_id: UUID = ACCOUNT_ID,
    action_hash: str = ACTION_HASH,
    policy_version: str = "policy-v1",
    policy_decision: PolicyDecision = PolicyDecision.ALLOW,
    issued_at: datetime = ISSUED_AT,
    expires_at: datetime = EXPIRES_AT,
    signing_key_id: str = SIGNING_KEY_ID,
) -> ReceiptPayload:
    return ReceiptPayload(
        receipt_version=RECEIPT_VERSION,
        receipt_id=RECEIPT_ID,
        account_id=account_id,
        authorization_request_id=AUTHORIZATION_REQUEST_ID,
        action_hash=action_hash,
        action_schema_version="action.material.v1",
        policy_version=policy_version,
        policy_decision=policy_decision,
        verification_status=VerificationStatus.VERIFIED,
        issued_at=issued_at,
        expires_at=expires_at,
        signing_key_id=signing_key_id,
    )


def receipt_service() -> ReceiptService:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.commit()
    return ReceiptService(
        session,
        signer=signer(),
        verifier=verifier(),
        audit_service=AuditService(session),
    )


def issue_receipt(service: ReceiptService) -> SignedReceipt:
    signed = service.issue_authorization_receipt(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_REQUEST_ID,
        authorization_result_id=AUTHORIZATION_RESULT_ID,
        action_hash=ACTION_HASH,
        action_schema_version="action.material.v1",
        policy_version="policy-v1",
        policy_decision=PolicyDecision.ALLOW,
        verification_status=VerificationStatus.VERIFIED,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        receipt_id=RECEIPT_ID,
        correlation_id=uuid4(),
    )
    service.session.commit()
    return signed


def test_receipt_issuance_persists_signed_safe_payload() -> None:
    service = receipt_service()
    signed = issue_receipt(service)

    persisted = service.session.scalar(select(Receipt).where(Receipt.receipt_id == RECEIPT_ID))
    assert persisted is not None
    assert signed.payload.receipt_id == RECEIPT_ID
    assert persisted.action_hash == ACTION_HASH
    assert persisted.signing_key_id == SIGNING_KEY_ID
    assert persisted.signature == signed.signature
    assert persisted.canonical_payload == signed.payload.to_public_dict()
    assert persisted.authorization_request_id == AUTHORIZATION_REQUEST_ID
    assert persisted.authorization_result_id == AUTHORIZATION_RESULT_ID
    assert persisted.receipt_hash == hashlib.sha256(
        canonical_receipt_json(signed.payload).encode("utf-8")
    ).hexdigest()


def test_valid_signature_verification() -> None:
    signed = signer().sign(payload())

    result = verifier().verify(signed, now=ISSUED_AT + timedelta(seconds=1))

    assert result.status is ReceiptVerificationStatus.SIGNATURE_VALID
    assert result.signature_valid is True
    assert result.currently_executable is True


def test_stable_canonical_receipt_vector() -> None:
    signed = signer().sign(payload())
    canonical = canonical_receipt_json(signed.payload)

    assert canonical == EXPECTED_CANONICAL_RECEIPT
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == (
        EXPECTED_CANONICAL_RECEIPT_SHA256
    )
    assert signed.signature == EXPECTED_SIGNATURE


def test_deterministic_serialization() -> None:
    first = payload()
    second = ReceiptPayload(
        receipt_version=RECEIPT_VERSION,
        receipt_id=RECEIPT_ID,
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_REQUEST_ID,
        action_hash=ACTION_HASH,
        action_schema_version="action.material.v1",
        policy_version="policy-v1",
        policy_decision=PolicyDecision.ALLOW,
        verification_status=VerificationStatus.VERIFIED,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_key_id=SIGNING_KEY_ID,
    )

    assert canonical_receipt_json(first) == canonical_receipt_json(second)
    assert signer().sign(first).signature == signer().sign(second).signature


@pytest.mark.parametrize(
    "tampered_payload",
    [
        payload(action_hash="f" * 64),
        payload(account_id=OTHER_ACCOUNT_ID),
        payload(policy_version="policy-v2"),
        payload(policy_decision=PolicyDecision.BLOCK),
        payload(issued_at=ISSUED_AT + timedelta(seconds=1)),
        payload(expires_at=EXPIRES_AT + timedelta(seconds=1)),
        payload(signing_key_id="receipt-test-key-rotated"),
    ],
)
def test_bound_field_tampering_invalidates_signature(tampered_payload: ReceiptPayload) -> None:
    original = signer().sign(payload())
    tampered = SignedReceipt(payload=tampered_payload, signature=original.signature)
    result = verifier().verify(tampered, now=ISSUED_AT + timedelta(seconds=1))

    assert result.status in {
        ReceiptVerificationStatus.SIGNATURE_INVALID,
        ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY,
    }
    assert result.signature_valid is False


def test_malformed_receipt_rejected() -> None:
    signed = SignedReceipt(
        payload=replace(payload(), policy_version=""),
        signature=signer().sign(payload()).signature,
    )

    result = verifier().verify(signed, now=ISSUED_AT + timedelta(seconds=1))

    assert result.status is ReceiptVerificationStatus.RECEIPT_MALFORMED


def test_expired_receipt_distinguished_from_invalid_signature() -> None:
    signed = signer().sign(payload(expires_at=EXPIRES_AT))

    result = verifier().verify(signed, now=EXPIRES_AT + timedelta(seconds=1))

    assert result.status is ReceiptVerificationStatus.RECEIPT_EXPIRED
    assert result.signature_valid is True
    assert result.currently_executable is False


def test_unknown_signing_key_rejected() -> None:
    signed = signer().sign(payload())

    result = Ed25519ReceiptVerifier({}).verify(signed, now=ISSUED_AT)

    assert result.status is ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY
    assert result.signature_valid is False


def test_cross_tenant_receipt_retrieval_denied() -> None:
    service = receipt_service()
    issue_receipt(service)

    with pytest.raises(CrossTenantReceiptAccess):
        service.get(account_id=OTHER_ACCOUNT_ID, receipt_id=RECEIPT_ID)


def test_private_key_never_appears_in_persisted_or_public_receipt() -> None:
    service = receipt_service()
    signed = issue_receipt(service)
    persisted = service.session.scalar(select(Receipt).where(Receipt.receipt_id == RECEIPT_ID))
    assert persisted is not None

    persisted_repr = repr(persisted.__dict__)
    public_repr = repr(signed.to_public_dict())

    assert PRIVATE_KEY_B64 not in persisted_repr
    assert PRIVATE_KEY_B64 not in public_repr
    assert "private_key" not in persisted_repr
    assert "private_key" not in public_repr


def test_receipt_service_audits_issue_and_verification_results() -> None:
    service = receipt_service()
    correlation_id = uuid4()
    signed = service.issue_authorization_receipt(
        account_id=ACCOUNT_ID,
        authorization_request_id=AUTHORIZATION_REQUEST_ID,
        action_hash=ACTION_HASH,
        action_schema_version="action.material.v1",
        policy_version="policy-v1",
        policy_decision=PolicyDecision.ALLOW,
        verification_status=VerificationStatus.VERIFIED,
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        receipt_id=RECEIPT_ID,
        correlation_id=correlation_id,
    )
    service.verify(
        signed_receipt=signed,
        account_id=ACCOUNT_ID,
        correlation_id=correlation_id,
        now=ISSUED_AT + timedelta(seconds=1),
    )
    service.session.commit()

    timeline = AuditService(service.session).timeline_for_correlation(
        account_id=ACCOUNT_ID,
        correlation_id=correlation_id,
    )

    assert [event.event_type for event in timeline] == [
        AuditEventType.RECEIPT_ISSUED,
        AuditEventType.RECEIPT_VERIFICATION_SUCCEEDED,
    ]
    for event in timeline:
        payload_repr = repr(event.payload)
        assert PRIVATE_KEY_B64 not in payload_repr
        assert "private_key" not in payload_repr


def test_receipt_canonicalization_rejects_ambiguous_values() -> None:
    with pytest.raises(CanonicalizationError):
        canonical_receipt_json(replace(payload(), issued_at=datetime(2026, 9, 10, 12, 0, 0)))
