from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import select

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import CreditLedgerEntry
from outcome.ledger import LedgerService, LedgerTransaction


class ReservationState(StrEnum):
    ACTIVE = "ACTIVE"
    SETTLED = "SETTLED"
    RELEASED = "RELEASED"
    EXPIRED = "EXPIRED"


class ReservationError(StrEnum):
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    CONFLICTING_REQUEST = "CONFLICTING_REQUEST"
    EXPIRED_RESERVATION = "EXPIRED_RESERVATION"
    SETTLEMENT_EXCEEDS_RESERVATION = "SETTLEMENT_EXCEEDS_RESERVATION"
    REDIS_UNAVAILABLE = "REDIS_UNAVAILABLE"
    SPEND_QUARANTINED = "SPEND_QUARANTINED"
    CROSS_TENANT_ACCESS = "CROSS_TENANT_ACCESS"
    NOT_FOUND = "NOT_FOUND"
    DURABLE_MISMATCH = "DURABLE_MISMATCH"


class ReservationUnavailable(RuntimeError):
    def __init__(self, error: ReservationError) -> None:
        super().__init__(error.value)
        self.error = error


class ReservationInsufficientFunds(ValueError):
    pass


class ReservationConflict(ValueError):
    pass


@dataclass(frozen=True)
class Reservation:
    reservation_id: UUID
    account_id: UUID
    request_id: UUID
    maximum_reserved_micro_usd: int
    state: ReservationState
    created_at: datetime
    expires_at: datetime
    ledger_transaction_id: UUID | None = None


@dataclass(frozen=True)
class ReconciliationFinding:
    code: str
    account_id: UUID
    reservation_id: UUID | None
    details: dict[str, object]


@dataclass(frozen=True)
class ReconciliationReport:
    account_id: UUID
    ledger_available_micro_usd: int
    active_reserved_micro_usd: int
    findings: tuple[ReconciliationFinding, ...]
    quarantined: bool


RESERVE_SCRIPT = """
if redis.call('EXISTS', KEYS[4]) == 1 then
  return {'QUARANTINED'}
end

local existing_id = redis.call('GET', KEYS[2])
if existing_id then
  local existing_key = ARGV[10] .. existing_id
  if redis.call('EXISTS', existing_key) == 0 then
    redis.call('DEL', KEYS[2])
  else
    local existing_amount = redis.call('HGET', existing_key, 'maximum_reserved_micro_usd')
    local existing_state = redis.call('HGET', existing_key, 'state')
    if existing_amount == ARGV[4] and existing_state == 'ACTIVE' then
      return {'EXISTING', existing_id}
    end
    return {'CONFLICT', existing_id}
  end
end

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[7])
local active_ids = redis.call('ZRANGE', KEYS[1], 0, -1)
local active_total = 0
for _, reservation_id in ipairs(active_ids) do
      local reservation_key = ARGV[10] .. reservation_id
  if redis.call('EXISTS', reservation_key) == 1
      and redis.call('HGET', reservation_key, 'state') == 'ACTIVE' then
    active_total = active_total + tonumber(redis.call(
      'HGET',
      reservation_key,
      'maximum_reserved_micro_usd'
    ))
  else
    redis.call('ZREM', KEYS[1], reservation_id)
  end
end

if tonumber(ARGV[5]) - active_total < tonumber(ARGV[4]) then
  return {'INSUFFICIENT_FUNDS', tostring(active_total)}
end

redis.call(
  'HSET',
  KEYS[3],
  'reservation_id', ARGV[3],
  'account_id', ARGV[1],
  'request_id', ARGV[2],
  'maximum_reserved_micro_usd', ARGV[4],
  'state', 'ACTIVE',
  'created_at', ARGV[6],
  'expires_at', ARGV[9]
)
redis.call('EXPIRE', KEYS[3], ARGV[11])
redis.call('SET', KEYS[2], ARGV[3], 'EX', ARGV[11])
redis.call('ZADD', KEYS[1], ARGV[8], ARGV[3])
return {'CREATED', ARGV[3]}
"""


class ReservationService:
    def __init__(
        self,
        *,
        redis: Redis,
        ledger_service: LedgerService,
        audit_service: AuditService,
    ) -> None:
        self.redis = redis
        self.ledger_service = ledger_service
        self.audit_service = audit_service

    def reserve(
        self,
        *,
        account_id: UUID,
        request_id: UUID,
        amount_micro_usd: int,
        ttl_seconds: int,
    ) -> Reservation:
        if amount_micro_usd <= 0:
            raise ValueError("amount_micro_usd must be positive")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        available = self.ledger_service.balance_micro_usd(account_id=account_id)
        reservation_id = uuid4()
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=ttl_seconds)

        try:
            result = self.redis.eval(
                RESERVE_SCRIPT,
                4,
                self._account_active_key(account_id),
                self._request_key(account_id, request_id),
                self._reservation_key(reservation_id),
                self._quarantine_key(account_id),
                str(account_id),
                str(request_id),
                str(reservation_id),
                str(amount_micro_usd),
                str(available),
                now.isoformat(),
                str(int(now.timestamp())),
                str(int(expires_at.timestamp())),
                expires_at.isoformat(),
                self._reservation_key_prefix(),
                str(ttl_seconds),
            )
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error

        status = self._decode(result[0])
        if status == "QUARANTINED":
            raise ReservationUnavailable(ReservationError.SPEND_QUARANTINED)
        if status == "INSUFFICIENT_FUNDS":
            raise ReservationInsufficientFunds("insufficient available prepaid credits")
        if status == "CONFLICT":
            raise ReservationConflict("request_id reused with conflicting reservation parameters")

        resolved_id = UUID(self._decode(result[1]))
        reservation = self.inspect(reservation_id=resolved_id, account_id=account_id)
        if reservation is None:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE)
        if status == "CREATED":
            self.audit_service.append_event(
                account_id=account_id,
                event_type=AuditEventType.CREDIT_RESERVED,
                correlation_id=request_id,
                request_id=request_id,
                payload={
                    "reservation_id": reservation.reservation_id,
                    "maximum_reserved_micro_usd": amount_micro_usd,
                    "available_micro_usd": available,
                    "reservation_state": reservation.state.value,
                    "reason_codes": ["CREDIT_RESERVED"],
                },
            )
        return reservation

    def settle(
        self,
        *,
        reservation_id: UUID,
        account_id: UUID,
        final_amount_micro_usd: int,
    ) -> LedgerTransaction:
        reservation = self.inspect(reservation_id=reservation_id, account_id=account_id)
        if reservation is None:
            raise ReservationUnavailable(ReservationError.EXPIRED_RESERVATION)
        if reservation.account_id != account_id:
            raise ReservationUnavailable(ReservationError.CROSS_TENANT_ACCESS)
        if reservation.state is not ReservationState.ACTIVE:
            raise ReservationUnavailable(ReservationError.EXPIRED_RESERVATION)
        if final_amount_micro_usd > reservation.maximum_reserved_micro_usd:
            raise ReservationConflict("settlement exceeds reserved amount")

        transaction = self.ledger_service.settle_reservation(
            account_id=account_id,
            amount_micro_usd=final_amount_micro_usd,
            idempotency_key=f"reservation:settle:{reservation_id}",
            correlation_id=reservation.request_id,
        )
        try:
            self.redis.hset(
                self._reservation_key(reservation_id),
                mapping={
                    "state": ReservationState.SETTLED.value,
                    "ledger_transaction_id": str(transaction.transaction_id),
                },
            )
            self.redis.zrem(self._account_active_key(account_id), str(reservation_id))
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error

        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.RESERVATION_SETTLED,
            correlation_id=reservation.request_id,
            request_id=reservation.request_id,
            payload={
                "reservation_id": reservation_id,
                "ledger_transaction_id": transaction.transaction_id,
                "maximum_reserved_micro_usd": reservation.maximum_reserved_micro_usd,
                "cost_amount_minor": final_amount_micro_usd,
                "currency": "USD",
                "reservation_state": ReservationState.SETTLED.value,
                "reason_codes": ["RESERVATION_SETTLED"],
            },
        )
        return transaction

    def release(self, *, reservation_id: UUID, account_id: UUID) -> Reservation | None:
        reservation = self.inspect(reservation_id=reservation_id, account_id=account_id)
        if reservation is None:
            return None
        if reservation.account_id != account_id:
            raise ReservationUnavailable(ReservationError.CROSS_TENANT_ACCESS)
        if reservation.state is ReservationState.RELEASED:
            return reservation
        if reservation.state is not ReservationState.ACTIVE:
            return reservation

        try:
            self.redis.hset(
                self._reservation_key(reservation_id),
                mapping={"state": ReservationState.RELEASED.value},
            )
            self.redis.zrem(self._account_active_key(account_id), str(reservation_id))
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error

        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.CREDIT_RELEASED,
            correlation_id=reservation.request_id,
            request_id=reservation.request_id,
            payload={
                "reservation_id": reservation_id,
                "maximum_reserved_micro_usd": reservation.maximum_reserved_micro_usd,
                "reservation_state": ReservationState.RELEASED.value,
                "reason_codes": ["RESERVATION_RELEASED"],
            },
        )
        released = self.inspect(reservation_id=reservation_id, account_id=account_id)
        return released or reservation

    def inspect(self, *, reservation_id: UUID, account_id: UUID) -> Reservation | None:
        try:
            data = self.redis.hgetall(self._reservation_key(reservation_id))
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error
        if not data:
            self._audit_expiration_once(account_id=account_id, reservation_id=reservation_id)
            return None
        reservation = self._reservation_from_hash(data)
        if reservation.account_id != account_id:
            raise ReservationUnavailable(ReservationError.CROSS_TENANT_ACCESS)
        return reservation

    def reconcile(self, *, account_id: UUID) -> ReconciliationReport:
        ledger_available = self.ledger_service.balance_micro_usd(account_id=account_id)
        findings: list[ReconciliationFinding] = []
        active_reserved = 0
        try:
            reservation_ids = [
                UUID(self._decode(value))
                for value in self.redis.zrange(self._account_active_key(account_id), 0, -1)
            ]
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error

        for reservation_id in reservation_ids:
            reservation = self.inspect(reservation_id=reservation_id, account_id=account_id)
            if reservation is None:
                findings.append(
                    ReconciliationFinding(
                        code="ORPHAN_REDIS_RESERVATION",
                        account_id=account_id,
                        reservation_id=reservation_id,
                        details={},
                    )
                )
                continue
            if reservation.state is ReservationState.ACTIVE:
                active_reserved += reservation.maximum_reserved_micro_usd
                if self._has_durable_settlement(
                    account_id=account_id,
                    request_id=reservation.request_id,
                ):
                    findings.append(
                        ReconciliationFinding(
                            code="STALE_ACTIVE_REDIS_AFTER_DURABLE_SETTLEMENT",
                            account_id=account_id,
                            reservation_id=reservation_id,
                            details={"reservation_state": reservation.state.value},
                        )
                    )
            if (
                reservation.state is ReservationState.SETTLED
                and reservation.ledger_transaction_id is None
            ):
                findings.append(
                    ReconciliationFinding(
                        code="SETTLED_REDIS_WITHOUT_LEDGER_TRANSACTION",
                        account_id=account_id,
                        reservation_id=reservation_id,
                        details={"reservation_state": reservation.state.value},
                    )
                )

        if active_reserved > ledger_available:
            findings.append(
                ReconciliationFinding(
                    code="AVAILABLE_SPEND_DIVERGENCE",
                    account_id=account_id,
                    reservation_id=None,
                    details={
                        "active_reserved_micro_usd": active_reserved,
                        "ledger_available_micro_usd": ledger_available,
                    },
                )
            )

        if findings:
            self._quarantine(account_id=account_id, findings=findings)

        return ReconciliationReport(
            account_id=account_id,
            ledger_available_micro_usd=ledger_available,
            active_reserved_micro_usd=active_reserved,
            findings=tuple(findings),
            quarantined=bool(findings),
        )

    def _quarantine(self, *, account_id: UUID, findings: list[ReconciliationFinding]) -> None:
        try:
            self.redis.set(self._quarantine_key(account_id), "1")
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.SPEND_QUARANTINED,
            correlation_id=uuid4(),
            payload={
                "reason_codes": [finding.code for finding in findings],
                "reservation_state": "QUARANTINED",
            },
        )
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.RECONCILIATION_MISMATCH,
            correlation_id=uuid4(),
            payload={"reason_codes": [finding.code for finding in findings]},
        )

    def _audit_expiration_once(self, *, account_id: UUID, reservation_id: UUID) -> None:
        try:
            should_audit = self.redis.set(
                f"outcome:reservations:expired_audit:{account_id}:{reservation_id}",
                "1",
                nx=True,
                ex=86_400,
            )
        except RedisError as error:
            raise ReservationUnavailable(ReservationError.REDIS_UNAVAILABLE) from error
        if not should_audit:
            return
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.RESERVATION_EXPIRED,
            correlation_id=uuid4(),
            payload={
                "reservation_id": reservation_id,
                "reservation_state": ReservationState.EXPIRED.value,
                "reason_codes": ["RESERVATION_EXPIRED"],
            },
        )

    def _has_durable_settlement(self, *, account_id: UUID, request_id: UUID) -> bool:
        return (
            self.ledger_service.session.scalar(
                select(CreditLedgerEntry.id)
                .where(CreditLedgerEntry.account_id == account_id)
                .where(CreditLedgerEntry.reference_id == request_id)
                .where(CreditLedgerEntry.entry_type == "reservation_settlement")
                .limit(1)
            )
            is not None
        )

    def _reservation_from_hash(self, data: dict[Any, Any]) -> Reservation:
        decoded = {self._decode(key): self._decode(value) for key, value in data.items()}
        return Reservation(
            reservation_id=UUID(decoded["reservation_id"]),
            account_id=UUID(decoded["account_id"]),
            request_id=UUID(decoded["request_id"]),
            maximum_reserved_micro_usd=int(decoded["maximum_reserved_micro_usd"]),
            state=ReservationState(decoded["state"]),
            created_at=datetime.fromisoformat(decoded["created_at"]),
            expires_at=datetime.fromisoformat(decoded["expires_at"]),
            ledger_transaction_id=UUID(decoded["ledger_transaction_id"])
            if decoded.get("ledger_transaction_id")
            else None,
        )

    def _account_active_key(self, account_id: UUID) -> str:
        return f"outcome:reservations:active:{account_id}"

    def _request_key(self, account_id: UUID, request_id: UUID) -> str:
        return f"outcome:reservations:request:{account_id}:{request_id}"

    def _reservation_key(self, reservation_id: UUID) -> str:
        return f"{self._reservation_key_prefix()}{reservation_id}"

    def _reservation_key_prefix(self) -> str:
        return "outcome:reservations:reservation:"

    def _quarantine_key(self, account_id: UUID) -> str:
        return f"outcome:reservations:quarantine:{account_id}"

    def _decode(self, value: object) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)
