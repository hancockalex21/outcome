from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from outcome.actions import ActionBindingContext, action_hash
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Account, AuditEvent
from outcome.domain import PolicyDecision, VerificationStatus
from outcome.execution import (
    ExecutionAuthorizationRequest,
    ExecutionAuthorizationStatus,
    ExecutionAuthorizationValidator,
)
from outcome.receipts import RECEIPT_VERSION, Ed25519ReceiptVerifier, ReceiptPayload, SignedReceipt
from tests.test_api_keys import build_session
from tests.test_receipt_service import SIGNING_KEY_ID, signer, verifier

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
RECEIPT_ID = UUID("66666666-6666-4666-8666-666666666666")
AUTHORIZATION_REQUEST_ID = UUID("77777777-7777-4777-8777-777777777777")
ISSUED_AT = datetime(2026, 9, 10, 12, 0, 0, tzinfo=UTC)
EXPIRES_AT = datetime(2026, 9, 10, 12, 5, 0, tzinfo=UTC)
NOW = datetime(2026, 9, 10, 12, 1, 0, tzinfo=UTC)
MATERIAL = {
    "merchant": "example-market",
    "amount_micro_usd": 12_500_000,
    "currency": "USD",
    "destination": "acct_merchant_123",
    "recipient": "customer-123",
    "sku": "verification-standard",
    "quantity": 1,
    "resource_id": "resource-abc",
}


def bound_action_hash(
    *,
    material: dict[str, object] = MATERIAL,
    account_id: UUID = ACCOUNT_ID,
    policy_version: str = "policy-v1",
    action_schema_version: str = "action.material.v1",
    expires_at: datetime = EXPIRES_AT,
) -> str:
    return action_hash(
        material=material,
        binding_context=ActionBindingContext(
            account_id=account_id,
            policy_version=policy_version,
            action_schema_version=action_schema_version,
            authorization_expires_at=expires_at,
        ),
    )


def signed_receipt(
    *,
    account_id: UUID = ACCOUNT_ID,
    policy_version: str = "policy-v1",
    action_schema_version: str = "action.material.v1",
    policy_decision: PolicyDecision = PolicyDecision.ALLOW,
    expires_at: datetime = EXPIRES_AT,
    signing_key_id: str = SIGNING_KEY_ID,
) -> SignedReceipt:
    return signer().sign(
        ReceiptPayload(
            receipt_version=RECEIPT_VERSION,
            receipt_id=RECEIPT_ID,
            account_id=account_id,
            authorization_request_id=AUTHORIZATION_REQUEST_ID,
            action_hash=bound_action_hash(
                account_id=account_id,
                policy_version=policy_version,
                action_schema_version=action_schema_version,
                expires_at=expires_at,
            ),
            action_schema_version=action_schema_version,
            policy_version=policy_version,
            policy_decision=policy_decision,
            verification_status=VerificationStatus.VERIFIED,
            issued_at=ISSUED_AT,
            expires_at=expires_at,
            signing_key_id=signing_key_id,
        )
    )


def request(
    *,
    receipt: SignedReceipt | None = None,
    material: dict[str, object] = MATERIAL,
    action_schema_version: str = "action.material.v1",
    account_id: UUID = ACCOUNT_ID,
    now: datetime = NOW,
    ephemeral: dict[str, object] | None = None,
    supplied_action_hash: str | None = None,
) -> ExecutionAuthorizationRequest:
    return ExecutionAuthorizationRequest(
        signed_receipt=receipt or signed_receipt(),
        proposed_material=material,
        proposed_action_schema_version=action_schema_version,
        authenticated_account_id=account_id,
        current_timestamp=now,
        ephemeral=ephemeral,
        supplied_action_hash=supplied_action_hash,
    )


def validate(
    validation_request: ExecutionAuthorizationRequest,
    *,
    audit_service: AuditService | None = None,
) -> ExecutionAuthorizationStatus:
    result = ExecutionAuthorizationValidator(
        receipt_verifier=verifier(),
        audit_service=audit_service,
    ).validate(validation_request, correlation_id=uuid4())
    return result.status


def test_valid_allow_receipt_exact_action_authorized() -> None:
    result = ExecutionAuthorizationValidator(receipt_verifier=verifier()).validate(
        request(),
        correlation_id=uuid4(),
    )

    assert result.status is ExecutionAuthorizationStatus.AUTHORIZED
    assert result.executable is True
    assert result.policy_decision is PolicyDecision.ALLOW
    assert result.verification_status is VerificationStatus.VERIFIED


def test_changed_material_amount_mismatches() -> None:
    changed = dict(MATERIAL)
    changed["amount_micro_usd"] = 12_500_001

    assert validate(request(material=changed)) is ExecutionAuthorizationStatus.ACTION_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("merchant", "other-market"),
        ("destination", "acct_merchant_456"),
        ("recipient", "customer-456"),
        ("resource_id", "resource-def"),
        ("sku", "verification-high"),
        ("quantity", 2),
    ],
)
def test_changed_material_identity_fields_mismatch(field: str, value: object) -> None:
    changed = dict(MATERIAL)
    changed[field] = value

    assert validate(request(material=changed)) is ExecutionAuthorizationStatus.ACTION_MISMATCH


def test_changed_ephemeral_request_id_still_authorized() -> None:
    first = request(ephemeral={"request_id": "first"})
    second = request(ephemeral={"request_id": "second"})

    assert validate(first) is ExecutionAuthorizationStatus.AUTHORIZED
    assert validate(second) is ExecutionAuthorizationStatus.AUTHORIZED


def test_changed_ephemeral_timestamp_and_nonce_still_authorized() -> None:
    validation_request = request(
        ephemeral={
            "client_timestamp": "2026-09-10T12:01:00Z",
            "nonce": "different",
        }
    )

    assert validate(validation_request) is ExecutionAuthorizationStatus.AUTHORIZED


def test_invalid_signature_rejected() -> None:
    original = signed_receipt()
    tampered = SignedReceipt(payload=original.payload, signature="A" + original.signature[1:])

    assert validate(request(receipt=tampered)) is ExecutionAuthorizationStatus.INVALID_SIGNATURE


def test_expired_receipt_rejected() -> None:
    receipt = signed_receipt(expires_at=EXPIRES_AT)

    assert validate(
        request(receipt=receipt, now=EXPIRES_AT + timedelta(seconds=1))
    ) is ExecutionAuthorizationStatus.EXPIRED_RECEIPT


def test_unknown_signing_key_rejected() -> None:
    result = ExecutionAuthorizationValidator(
        receipt_verifier=Ed25519ReceiptVerifier({}),
    ).validate(request(), correlation_id=uuid4())

    assert result.status is ExecutionAuthorizationStatus.UNKNOWN_SIGNING_KEY


def test_malformed_receipt_rejected() -> None:
    original = signed_receipt()
    malformed = SignedReceipt(
        payload=replace(original.payload, policy_version=""),
        signature=original.signature,
    )

    assert validate(request(receipt=malformed)) is ExecutionAuthorizationStatus.MALFORMED_RECEIPT


@pytest.mark.parametrize(
    "decision",
    [
        PolicyDecision.BLOCK,
        PolicyDecision.RETRY_HIGHER_ASSURANCE,
        PolicyDecision.ESCALATE,
    ],
)
def test_non_allow_decisions_are_not_executable(decision: PolicyDecision) -> None:
    receipt = signed_receipt(policy_decision=decision)

    assert validate(request(receipt=receipt)) is ExecutionAuthorizationStatus.DECISION_NOT_ALLOWED


def test_cross_account_receipt_fails_account_mismatch() -> None:
    receipt = signed_receipt(account_id=OTHER_ACCOUNT_ID)

    assert validate(request(receipt=receipt, account_id=ACCOUNT_ID)) is (
        ExecutionAuthorizationStatus.ACCOUNT_MISMATCH
    )


def test_action_schema_mismatch_rejected() -> None:
    assert validate(
        request(action_schema_version="action.material.v2")
    ) is ExecutionAuthorizationStatus.SCHEMA_MISMATCH


def test_tampered_policy_version_signature_rejected() -> None:
    original = signed_receipt()
    tampered = SignedReceipt(
        payload=replace(original.payload, policy_version="policy-v2"),
        signature=original.signature,
    )

    assert validate(request(receipt=tampered)) is ExecutionAuthorizationStatus.INVALID_SIGNATURE


def test_caller_supplied_fake_action_hash_cannot_bypass_recomputation() -> None:
    changed = dict(MATERIAL)
    changed["amount_micro_usd"] = 99_000_000

    assert validate(
        request(
            material=changed,
            supplied_action_hash=signed_receipt().payload.action_hash,
        )
    ) is ExecutionAuthorizationStatus.ACTION_MISMATCH


def test_raw_material_action_is_not_persisted_to_audit() -> None:
    session = build_session()
    account = session.scalar(select(Account))
    assert account is not None
    account.id = ACCOUNT_ID
    session.commit()
    audit_service = AuditService(session)
    correlation_id = uuid4()
    secret_material = dict(MATERIAL)
    secret_material["merchant"] = "merchant-secret-never-audit"

    result = ExecutionAuthorizationValidator(
        receipt_verifier=verifier(),
        audit_service=audit_service,
    ).validate(
        request(material=secret_material),
        correlation_id=correlation_id,
    )
    session.commit()

    assert result.status is ExecutionAuthorizationStatus.ACTION_MISMATCH
    timeline = audit_service.timeline_for_correlation(
        account_id=ACCOUNT_ID,
        correlation_id=correlation_id,
    )
    persisted_events = session.scalars(select(AuditEvent)).all()

    assert [event.event_type for event in timeline] == [
        AuditEventType.EXECUTION_AUTHORIZATION_REJECTED
    ]
    assert persisted_events
    for event in persisted_events:
        payload_repr = repr(event.payload)
        assert "merchant-secret-never-audit" not in payload_repr
        assert "amount_micro_usd" not in payload_repr
