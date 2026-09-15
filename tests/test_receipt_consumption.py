from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditService
from outcome.db.metadata import metadata
from outcome.db.models import Account, AuditEvent, ReceiptConsumption
from outcome.domain import PolicyDecision, VerificationStatus
from outcome.execution import (
    ExecutionAuthorizationRequest,
    ExecutionAuthorizationValidator,
    ReceiptConsumptionService,
    ReceiptConsumptionStatus,
)
from outcome.receipts import RECEIPT_VERSION, ReceiptPayload
from tests.test_execution_authorization import (
    ACCOUNT_ID,
    AUTHORIZATION_REQUEST_ID,
    EXPIRES_AT,
    ISSUED_AT,
    MATERIAL,
    NOW,
    OTHER_ACCOUNT_ID,
    bound_action_hash,
)
from tests.test_receipt_service import SIGNING_KEY_ID, signer, verifier

EXECUTION_REQUEST_ID = UUID("88888888-8888-4888-8888-888888888888")
RECEIPT_ID = UUID("99999999-9999-4999-8999-999999999999")


def build_consumption_session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(Account(id=ACCOUNT_ID, display_name="Consumption", status="active"))
    session.commit()
    return session


def signed_receipt(
    *,
    receipt_id: UUID = RECEIPT_ID,
    account_id: UUID = ACCOUNT_ID,
    material: dict[str, object] = MATERIAL,
    decision: PolicyDecision = PolicyDecision.ALLOW,
    expires_at: datetime = EXPIRES_AT,
) -> object:
    return signer().sign(
        ReceiptPayload(
            receipt_version=RECEIPT_VERSION,
            receipt_id=receipt_id,
            account_id=account_id,
            authorization_request_id=AUTHORIZATION_REQUEST_ID,
            action_hash=bound_action_hash(
                material=material,
                account_id=account_id,
                expires_at=expires_at,
            ),
            action_schema_version="action.material.v1",
            policy_version="policy-v1",
            policy_decision=decision,
            verification_status=VerificationStatus.VERIFIED,
            issued_at=ISSUED_AT,
            expires_at=expires_at,
            signing_key_id=SIGNING_KEY_ID,
        )
    )


def authorization_request(
    *,
    receipt: object | None = None,
    material: dict[str, object] = MATERIAL,
    account_id: UUID = ACCOUNT_ID,
    now: datetime = NOW,
) -> ExecutionAuthorizationRequest:
    return ExecutionAuthorizationRequest(
        signed_receipt=receipt or signed_receipt(),
        proposed_material=material,
        proposed_action_schema_version="action.material.v1",
        authenticated_account_id=account_id,
        current_timestamp=now,
    )


def consumption_service(session: Session) -> ReceiptConsumptionService:
    audit_service = AuditService(session)
    validator = ExecutionAuthorizationValidator(
        receipt_verifier=verifier(),
        audit_service=audit_service,
    )
    return ReceiptConsumptionService(
        session,
        validator=validator,
        audit_service=audit_service,
    )


def consume(
    session: Session,
    *,
    execution_request_id: UUID = EXECUTION_REQUEST_ID,
    request: ExecutionAuthorizationRequest | None = None,
) -> object:
    return consumption_service(session).consume(
        authorization_request=request or authorization_request(),
        execution_request_id=execution_request_id,
        correlation_id=uuid4(),
    )


def count_consumptions(session: Session) -> int:
    return len(session.scalars(select(ReceiptConsumption)).all())


def test_first_valid_consume_succeeds() -> None:
    session = build_consumption_session()

    result = consume(session)
    session.commit()

    assert result.status is ReceiptConsumptionStatus.CONSUMED
    assert result.consumption_id is not None
    assert count_consumptions(session) == 1


def test_second_consume_with_different_execution_request_is_replay() -> None:
    session = build_consumption_session()
    first = consume(session)
    second = consume(session, execution_request_id=uuid4())

    assert first.status is ReceiptConsumptionStatus.CONSUMED
    assert second.status is ReceiptConsumptionStatus.ALREADY_CONSUMED
    assert second.consumption_id == first.consumption_id
    assert count_consumptions(session) == 1


def test_same_execution_request_retry_is_idempotent() -> None:
    session = build_consumption_session()
    first = consume(session)
    second = consume(session)

    assert first.status is ReceiptConsumptionStatus.CONSUMED
    assert second.status is ReceiptConsumptionStatus.IDEMPOTENT_REPLAY
    assert second.consumption_id == first.consumption_id
    assert count_consumptions(session) == 1


def test_concurrent_consumes_create_exactly_one_record() -> None:
    with TemporaryDirectory() as tempdir:
        database_path = Path(tempdir) / "consumption.db"
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False},
        )
        metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        setup_session = session_factory()
        setup_session.add(Account(id=ACCOUNT_ID, display_name="Concurrent", status="active"))
        setup_session.commit()
        setup_session.close()

        def attempt_consume(index: int) -> ReceiptConsumptionStatus:
            thread_session = session_factory()
            try:
                result = consume(
                    thread_session,
                    execution_request_id=uuid4(),
                )
                thread_session.commit()
                return result.status
            finally:
                thread_session.close()

        with ThreadPoolExecutor(max_workers=12) as executor:
            statuses = list(executor.map(attempt_consume, range(24)))

        verification_session = session_factory()
        try:
            assert statuses.count(ReceiptConsumptionStatus.CONSUMED) == 1
            assert statuses.count(ReceiptConsumptionStatus.ALREADY_CONSUMED) == 23
            assert count_consumptions(verification_session) == 1
        finally:
            verification_session.close()


def test_invalid_receipt_does_not_consume() -> None:
    session = build_consumption_session()
    receipt = signed_receipt()
    invalid = type(receipt)(payload=receipt.payload, signature="A" + receipt.signature[1:])

    result = consume(session, request=authorization_request(receipt=invalid))

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    assert count_consumptions(session) == 0


def test_expired_receipt_does_not_consume() -> None:
    session = build_consumption_session()
    receipt = signed_receipt(expires_at=EXPIRES_AT)

    result = consume(
        session,
        request=authorization_request(
            receipt=receipt,
            now=EXPIRES_AT + timedelta(seconds=1),
        ),
    )

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    assert count_consumptions(session) == 0


@pytest.mark.parametrize(
    "decision",
    [
        PolicyDecision.BLOCK,
        PolicyDecision.RETRY_HIGHER_ASSURANCE,
        PolicyDecision.ESCALATE,
    ],
)
def test_non_allow_receipts_do_not_consume(decision: PolicyDecision) -> None:
    session = build_consumption_session()
    result = consume(
        session,
        request=authorization_request(receipt=signed_receipt(decision=decision)),
    )

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    assert count_consumptions(session) == 0


def test_action_mismatch_does_not_consume() -> None:
    session = build_consumption_session()
    changed = dict(MATERIAL)
    changed["amount_micro_usd"] = 99_000_000

    result = consume(session, request=authorization_request(material=changed))

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    assert result.validation_status is not None
    assert count_consumptions(session) == 0


def test_cross_account_consume_rejected() -> None:
    session = build_consumption_session()
    result = consume(
        session,
        request=authorization_request(
            receipt=signed_receipt(account_id=OTHER_ACCOUNT_ID),
            account_id=ACCOUNT_ID,
        ),
    )

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    assert count_consumptions(session) == 0


def test_execution_request_id_conflict_rejected() -> None:
    session = build_consumption_session()
    first = consume(session)
    second_receipt = signed_receipt(receipt_id=uuid4())
    second = consume(
        session,
        request=authorization_request(receipt=second_receipt),
    )

    assert first.status is ReceiptConsumptionStatus.CONSUMED
    assert second.status is ReceiptConsumptionStatus.IDEMPOTENCY_CONFLICT
    assert count_consumptions(session) == 1


def test_db_uniqueness_prevents_double_consumption() -> None:
    session = build_consumption_session()
    first = consume(session)
    assert first.status is ReceiptConsumptionStatus.CONSUMED

    duplicate = ReceiptConsumption(
        id=uuid4(),
        account_id=ACCOUNT_ID,
        consumption_id=uuid4(),
        receipt_id=RECEIPT_ID,
        authorization_request_id=AUTHORIZATION_REQUEST_ID,
        action_hash=first.action_hash or "",
        consumed_at=NOW,
        execution_request_id=uuid4(),
    )
    session.add(duplicate)

    with pytest.raises(IntegrityError):
        session.flush()


def test_system_db_failure_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    session = build_consumption_session()
    service = ReceiptConsumptionService(
        session,
        validator=ExecutionAuthorizationValidator(receipt_verifier=verifier()),
        audit_service=AuditService(session),
    )

    def fail_flush() -> None:
        raise SQLAlchemyError("database unavailable")

    monkeypatch.setattr(session, "flush", fail_flush)

    result = service.consume(
        authorization_request=authorization_request(),
        execution_request_id=EXECUTION_REQUEST_ID,
        correlation_id=uuid4(),
    )

    assert result.status is ReceiptConsumptionStatus.SYSTEM_FAILURE


def test_raw_action_and_receipt_are_not_stored_in_audit() -> None:
    session = build_consumption_session()
    secret_material = dict(MATERIAL)
    secret_material["merchant"] = "raw-secret-merchant"
    correlation_id = uuid4()
    result = consumption_service(session).consume(
        authorization_request=authorization_request(material=secret_material),
        execution_request_id=EXECUTION_REQUEST_ID,
        correlation_id=correlation_id,
    )
    session.commit()

    assert result.status is ReceiptConsumptionStatus.NOT_AUTHORIZED
    events = session.scalars(select(AuditEvent)).all()
    assert events
    for event in events:
        payload_repr = repr(event.payload)
        assert "raw-secret-merchant" not in payload_repr
        assert "signed_receipt" not in payload_repr
        assert "signature" not in payload_repr


def test_consumption_records_cannot_be_mutated_through_service_api() -> None:
    methods = {
        name
        for name in dir(ReceiptConsumptionService)
        if not name.startswith("_") and callable(getattr(ReceiptConsumptionService, name))
    }

    assert methods == {"consume"}
