from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from outcome.db.models import (
    AccountFunding,
    AuthorizationRequest,
    BetaRegistration,
    CreditLedgerTransaction,
)
from outcome.ledger import LedgerTransactionType


@dataclass(frozen=True)
class BetaMetrics:
    registered_accounts: int
    accounts_with_authorization: int
    promotional_credit_issued_micro_usd: int
    authorization_usage_micro_usd: int
    customer_paid_funding_micro_usd: int
    service_credit_issued_micro_usd: int


def collect_beta_metrics(session: Session) -> BetaMetrics:
    registered = int(session.scalar(select(func.count()).select_from(BetaRegistration)) or 0)
    active = int(
        session.scalar(
            select(func.count(distinct(AuthorizationRequest.account_id))).join(
                BetaRegistration,
                BetaRegistration.account_id == AuthorizationRequest.account_id,
            )
        )
        or 0
    )
    return BetaMetrics(
        registered_accounts=registered,
        accounts_with_authorization=active,
        promotional_credit_issued_micro_usd=_sum_type(
            session, LedgerTransactionType.PROMOTIONAL_CREDIT
        ),
        authorization_usage_micro_usd=_sum_type(
            session, LedgerTransactionType.RESERVATION_SETTLEMENT
        ),
        customer_paid_funding_micro_usd=int(
            session.scalar(
                select(func.coalesce(func.sum(AccountFunding.amount_micro_usd), 0)).where(
                    AccountFunding.status == "SUCCEEDED",
                    AccountFunding.ledger_transaction_id.is_not(None),
                )
            )
            or 0
        ),
        service_credit_issued_micro_usd=_sum_type(session, LedgerTransactionType.SERVICE_CREDIT),
    )


def _sum_type(session: Session, transaction_type: LedgerTransactionType) -> int:
    return int(
        session.scalar(
            select(func.coalesce(func.sum(CreditLedgerTransaction.amount_micro_usd), 0)).where(
                CreditLedgerTransaction.transaction_type == transaction_type.value
            )
        )
        or 0
    )
