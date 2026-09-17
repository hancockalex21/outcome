from __future__ import annotations

import base64
from collections.abc import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from redis import Redis
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from outcome.audit import AuditService
from outcome.authorization import AuthorizationOrchestrator
from outcome.billing import AuthorizationBillingService
from outcome.core.config import get_settings
from outcome.core.logging import configure_logging
from outcome.db.metadata import metadata
from outcome.execution import ExecutionAuthorizationValidator
from outcome.ledger import LedgerService
from outcome.policies import PolicyEvaluationService
from outcome.pricing import (
    BillingMode,
    CapabilityName,
    CapabilityPricingConfig,
    InMemoryPricingConfigStore,
    PricingService,
)
from outcome.receipts import Ed25519ReceiptSigner, Ed25519ReceiptVerifier, ReceiptService
from outcome.reservations import ReservationService
from outcome.verification import VerificationOrchestrator

from .server import OutcomeApplicationServices, OutcomeMCPDependencies, create_mcp_server


def build_session_factory() -> Callable[[], Session]:
    settings = get_settings()
    engine = create_engine(settings.mcp_database_url)
    metadata.create_all(engine)
    return sessionmaker(bind=engine)


def build_application(session: Session) -> OutcomeApplicationServices:
    settings = get_settings()
    audit = AuditService(session)
    ledger = LedgerService(session, audit)
    pricing = PricingService(
        config_store=InMemoryPricingConfigStore(
            (
                CapabilityPricingConfig(
                    capability=CapabilityName.AUTHORIZE,
                    billing_mode=BillingMode.MANAGED,
                    pricing_config_version="mcp-managed-v1",
                    minimum_price_micro_usd=1_000_000,
                    included_evidence_budget_micro_usd=0,
                    expected_compute_cost_micro_usd=500_000,
                    expected_managed_supplier_cost_micro_usd=0,
                    target_gross_margin_bps=0,
                    maximum_retry_budget_micro_usd=0,
                    maximum_total_cost_micro_usd=1_000_000,
                    enabled=True,
                ),
                CapabilityPricingConfig(
                    capability=CapabilityName.VERIFY,
                    billing_mode=BillingMode.MANAGED,
                    pricing_config_version="mcp-verify-managed-v1",
                    minimum_price_micro_usd=1_000_000,
                    included_evidence_budget_micro_usd=0,
                    expected_compute_cost_micro_usd=500_000,
                    expected_managed_supplier_cost_micro_usd=0,
                    target_gross_margin_bps=0,
                    maximum_retry_budget_micro_usd=0,
                    maximum_total_cost_micro_usd=1_000_000,
                    enabled=True,
                ),
            )
        ),
        audit_service=audit,
    )
    signer = _receipt_signer()
    verifier = Ed25519ReceiptVerifier({signer.signing_key_id: signer.public_key_bytes()})
    receipt_service = ReceiptService(
        session,
        signer=signer,
        verifier=verifier,
        audit_service=audit,
    )
    reservation_service = ReservationService(
        redis=Redis.from_url(settings.redis_url),
        ledger_service=ledger,
        audit_service=audit,
    )
    billing_service = AuthorizationBillingService(
        session,
        pricing_service=pricing,
        reservation_service=reservation_service,
        ledger_service=ledger,
        audit_service=audit,
    )
    return OutcomeApplicationServices(
        verification_orchestrator=VerificationOrchestrator(session, audit_service=audit),
        authorization_orchestrator=AuthorizationOrchestrator(
            session,
            policy_service=PolicyEvaluationService(session, audit, clock=None),
            verification_orchestrator=VerificationOrchestrator(session, audit_service=audit),
            receipt_service=receipt_service,
            execution_validator=ExecutionAuthorizationValidator(
                receipt_verifier=verifier,
                audit_service=audit,
            ),
            billing_service=billing_service,
            audit_service=audit,
        ),
    )


def run() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    server = create_mcp_server(
        OutcomeMCPDependencies(
            session_factory=build_session_factory(),
            application_factory=build_application,
        )
    )
    server.run("stdio")


def _receipt_signer() -> Ed25519ReceiptSigner:
    settings = get_settings()
    if settings.mcp_receipt_private_key_b64:
        private_key_bytes = base64.urlsafe_b64decode(settings.mcp_receipt_private_key_b64)
        return Ed25519ReceiptSigner.from_private_key_bytes(
            signing_key_id=settings.mcp_receipt_signing_key_id,
            private_key_bytes=private_key_bytes,
        )
    return Ed25519ReceiptSigner(
        signing_key_id=settings.mcp_receipt_signing_key_id,
        private_key=Ed25519PrivateKey.generate(),
    )


__all__ = ["build_application", "build_session_factory", "run"]

