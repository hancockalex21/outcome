from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import UUID, uuid4

import pytest
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditEventType, AuditService
from outcome.db.metadata import metadata
from outcome.db.models import Account, AuditEvent
from outcome.ledger import LedgerService
from outcome.reservations import (
    ReconciliationReport,
    ReservationConflict,
    ReservationInsufficientFunds,
    ReservationService,
    ReservationState,
    ReservationUnavailable,
)
from outcome.reservations.service import ReservationError
from tests.test_api_keys import build_session


class NoopAuditService(AuditService):
    def __init__(self) -> None:
        pass

    def append_event(self, **_: Any) -> None:
        return None


@pytest.fixture()
def redis_client() -> Iterator[Redis]:
    client = Redis(host="127.0.0.1", port=6379, db=15)
    try:
        client.ping()
    except RedisError:
        pytest.skip("local Redis is not available")
    client.flushdb()
    yield client
    client.flushdb()


def account_id_from(session: Session) -> UUID:
    account_id = session.scalar(select(Account.id))
    assert account_id is not None
    return account_id


def build_reservation_service(
    redis_client: Redis,
    session: Session,
    *,
    initial_balance: int = 10_000_000,
) -> tuple[ReservationService, UUID]:
    account_id = account_id_from(session)
    LedgerService(session).fund_account(
        account_id=account_id,
        amount_micro_usd=initial_balance,
        idempotency_key=f"fund:{uuid4()}",
        correlation_id=uuid4(),
    )
    session.commit()
    service = ReservationService(
        redis=redis_client,
        ledger_service=LedgerService(session),
        audit_service=AuditService(session),
    )
    return service, account_id


def test_basic_reserve(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    request_id = uuid4()

    reservation = service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )
    session.commit()

    assert reservation.account_id == account_id
    assert reservation.request_id == request_id
    assert reservation.maximum_reserved_micro_usd == 1_000_000
    assert reservation.state is ReservationState.ACTIVE


def test_reserve_exactly_full_available_amount(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(
        redis_client,
        session,
        initial_balance=2_000_000,
    )

    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=2_000_000,
        ttl_seconds=60,
    )

    assert reservation.maximum_reserved_micro_usd == 2_000_000


def test_insufficient_funds(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(
        redis_client,
        session,
        initial_balance=1_000_000,
    )

    with pytest.raises(ReservationInsufficientFunds):
        service.reserve(
            account_id=account_id,
            request_id=uuid4(),
            amount_micro_usd=1_000_001,
            ttl_seconds=60,
        )


def test_100_concurrent_reservation_attempts_cannot_overspend(redis_client: Redis) -> None:
    with TemporaryDirectory() as directory:
        database_path = Path(directory) / "reservations.sqlite"
        engine = create_engine(
            f"sqlite:///{database_path}",
            connect_args={"check_same_thread": False},
        )
        metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)
        account_id = uuid4()
        with session_factory.begin() as session:
            session.add(Account(id=account_id, display_name="Concurrent", status="active"))
            LedgerService(session, NoopAuditService()).fund_account(
                account_id=account_id,
                amount_micro_usd=10_000_000,
                idempotency_key="fund",
                correlation_id=uuid4(),
            )

        def reserve_once(_: int) -> int:
            session = session_factory()
            try:
                service = ReservationService(
                    redis=redis_client,
                    ledger_service=LedgerService(session, NoopAuditService()),
                    audit_service=NoopAuditService(),
                )
                reservation = service.reserve(
                    account_id=account_id,
                    request_id=uuid4(),
                    amount_micro_usd=200_000,
                    ttl_seconds=60,
                )
                return reservation.maximum_reserved_micro_usd
            except ReservationInsufficientFunds:
                return 0
            finally:
                session.close()

        with ThreadPoolExecutor(max_workers=20) as executor:
            reserved_amounts = list(executor.map(reserve_once, range(100)))

    assert sum(reserved_amounts) <= 10_000_000
    assert sum(1 for amount in reserved_amounts if amount > 0) == 50


def test_duplicate_reservation_idempotency(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    request_id = uuid4()

    first = service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )
    second = service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    assert second.reservation_id == first.reservation_id


def test_conflicting_request_reuse(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    request_id = uuid4()
    service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    with pytest.raises(ReservationConflict):
        service.reserve(
            account_id=account_id,
            request_id=request_id,
            amount_micro_usd=2_000_000,
            ttl_seconds=60,
        )


def test_settle_below_reserved_amount(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=2_000_000,
        ttl_seconds=60,
    )

    transaction = service.settle(
        reservation_id=reservation.reservation_id,
        account_id=account_id,
        final_amount_micro_usd=1_250_000,
    )
    session.commit()

    assert transaction.transaction_id
    assert service.inspect(
        reservation_id=reservation.reservation_id,
        account_id=account_id,
    ).state is ReservationState.SETTLED
    assert LedgerService(session).balance_micro_usd(account_id=account_id) == 8_750_000


def test_settle_above_reserved_amount_rejected(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    with pytest.raises(ReservationConflict):
        service.settle(
            reservation_id=reservation.reservation_id,
            account_id=account_id,
            final_amount_micro_usd=1_000_001,
        )


def test_release(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    released = service.release(reservation_id=reservation.reservation_id, account_id=account_id)

    assert released is not None
    assert released.state is ReservationState.RELEASED
    service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=10_000_000,
        ttl_seconds=60,
    )


def test_duplicate_release(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    first = service.release(reservation_id=reservation.reservation_id, account_id=account_id)
    second = service.release(reservation_id=reservation.reservation_id, account_id=account_id)

    assert first is not None
    assert second is not None
    assert first.reservation_id == second.reservation_id
    assert second.state is ReservationState.RELEASED


def test_ttl_expiration(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=10_000_000,
        ttl_seconds=1,
    )

    time.sleep(1.2)

    assert service.inspect(reservation_id=reservation.reservation_id, account_id=account_id) is None
    session.commit()
    expiration_event = session.scalar(
        select(AuditEvent).where(AuditEvent.event_type == AuditEventType.RESERVATION_EXPIRED.value)
    )
    assert expiration_event is not None
    assert expiration_event.payload["reservation_id"] == str(reservation.reservation_id)
    service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=10_000_000,
        ttl_seconds=60,
    )


def test_late_settlement_after_expiration_rejected(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=1_000_000,
        ttl_seconds=1,
    )
    time.sleep(1.2)

    with pytest.raises(ReservationUnavailable) as error:
        service.settle(
            reservation_id=reservation.reservation_id,
            account_id=account_id,
            final_amount_micro_usd=500_000,
        )

    assert error.value.error is ReservationError.EXPIRED_RESERVATION


def test_redis_unavailable_fails_closed() -> None:
    session = build_session()
    account_id = account_id_from(session)
    LedgerService(session).fund_account(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="fund",
        correlation_id=uuid4(),
    )
    unavailable = Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.01)
    service = ReservationService(
        redis=unavailable,
        ledger_service=LedgerService(session),
        audit_service=AuditService(session),
    )

    with pytest.raises(ReservationUnavailable) as error:
        service.reserve(
            account_id=account_id,
            request_id=uuid4(),
            amount_micro_usd=1_000_000,
            ttl_seconds=60,
        )

    assert error.value.error is ReservationError.REDIS_UNAVAILABLE


def test_reconciliation_detects_orphan_reservation(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    orphan_id = uuid4()
    redis_client.zadd(f"outcome:reservations:active:{account_id}", {str(orphan_id): 9_999_999_999})

    report = service.reconcile(account_id=account_id)
    session.commit()

    assert report.quarantined
    assert finding_codes(report) == {"ORPHAN_REDIS_RESERVATION"}


def test_reconciliation_detects_durable_redis_mismatch(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    reservation_id = uuid4()
    request_id = uuid4()
    key = f"outcome:reservations:reservation:{reservation_id}"
    redis_client.hset(
        key,
        mapping={
            "reservation_id": str(reservation_id),
            "account_id": str(account_id),
            "request_id": str(request_id),
            "maximum_reserved_micro_usd": "1000000",
            "state": ReservationState.SETTLED.value,
            "created_at": "2026-09-10T00:00:00+00:00",
            "expires_at": "2026-09-10T00:05:00+00:00",
        },
    )
    redis_client.zadd(
        f"outcome:reservations:active:{account_id}",
        {str(reservation_id): 9_999_999_999},
    )

    report = service.reconcile(account_id=account_id)

    assert report.quarantined
    assert finding_codes(report) == {"SETTLED_REDIS_WITHOUT_LEDGER_TRANSACTION"}


def test_reconciliation_detects_stale_active_reservation_after_durable_settlement(
    redis_client: Redis,
) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    request_id = uuid4()
    reservation = service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )
    LedgerService(session).settle_reservation(
        account_id=account_id,
        amount_micro_usd=1_000_000,
        idempotency_key="external-settlement",
        correlation_id=request_id,
    )
    session.commit()

    report = service.reconcile(account_id=account_id)

    assert report.quarantined
    assert reservation.reservation_id in {
        finding.reservation_id for finding in report.findings
    }
    assert "STALE_ACTIVE_REDIS_AFTER_DURABLE_SETTLEMENT" in finding_codes(report)


def test_quarantined_account_cannot_create_new_reservation(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    orphan_id = uuid4()
    redis_client.zadd(f"outcome:reservations:active:{account_id}", {str(orphan_id): 9_999_999_999})
    service.reconcile(account_id=account_id)

    with pytest.raises(ReservationUnavailable) as error:
        service.reserve(
            account_id=account_id,
            request_id=uuid4(),
            amount_micro_usd=1_000_000,
            ttl_seconds=60,
        )

    assert error.value.error is ReservationError.SPEND_QUARANTINED


def test_cross_tenant_access_denied(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    other_account_id = uuid4()
    session.add(Account(id=other_account_id, display_name="Other", status="active"))
    session.commit()
    reservation = service.reserve(
        account_id=account_id,
        request_id=uuid4(),
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )

    with pytest.raises(ReservationUnavailable) as error:
        service.inspect(
            reservation_id=reservation.reservation_id,
            account_id=other_account_id,
        )

    assert error.value.error is ReservationError.CROSS_TENANT_ACCESS


def test_audit_events_for_reservation_lifecycle_are_safe(redis_client: Redis) -> None:
    session = build_session()
    service, account_id = build_reservation_service(redis_client, session)
    request_id = uuid4()
    reservation = service.reserve(
        account_id=account_id,
        request_id=request_id,
        amount_micro_usd=1_000_000,
        ttl_seconds=60,
    )
    service.release(reservation_id=reservation.reservation_id, account_id=account_id)
    session.commit()

    timeline = AuditService(session).timeline_for_correlation(
        account_id=account_id,
        correlation_id=request_id,
    )

    assert [event.event_type for event in timeline] == [
        AuditEventType.CREDIT_RESERVED,
        AuditEventType.CREDIT_RELEASED,
    ]
    assert "idempotency_key" not in repr([event.payload for event in timeline])
    assert "raw Redis" not in repr([event.payload for event in timeline])


def finding_codes(report: ReconciliationReport) -> set[str]:
    return {finding.code for finding in report.findings}
