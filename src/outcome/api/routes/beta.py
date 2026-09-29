from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from uuid import NAMESPACE_URL, uuid5

from fastapi import APIRouter, Header, HTTPException, Request, status
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from outcome.core.config import Settings
from outcome.onboarding import (
    BetaRegistrationConflict,
    BetaRegistrationCredentialAlreadyIssued,
    BetaRegistrationInput,
    BetaRegistrationLimitReached,
    BetaRegistrationService,
    BetaRegistrationUnavailable,
)
from outcome.schemas.onboarding import (
    BetaRegistrationRequest,
    BetaRegistrationResponse,
    StarterPolicySummary,
)

router = APIRouter(prefix="/v1/beta", tags=["controlled-beta"])


@dataclass(frozen=True)
class BetaRouteDependencies:
    settings: Settings
    session_factory: Callable[[], Session] | None
    redis: Redis | None


@router.post(
    "/register",
    response_model=BetaRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_beta(
    payload: BetaRegistrationRequest,
    request: Request,
    x_outcome_beta_token: str | None = Header(default=None, max_length=512),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=255),
) -> BetaRegistrationResponse:
    dependencies: BetaRouteDependencies = request.app.state.beta_registration
    settings = dependencies.settings
    if not settings.beta_registration_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    _rate_limit(request, dependencies)
    if not _valid_bootstrap_token(x_outcome_beta_token, settings):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid beta access")
    if idempotency_key is None or not idempotency_key.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="idempotency key required"
        )
    if dependencies.session_factory is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable")

    session = dependencies.session_factory()
    try:
        with session.begin():
            result = BetaRegistrationService(
                session,
                promotional_credit_micro_usd=settings.beta_promotional_credit_micro_usd,
                registration_limit=settings.beta_registration_limit,
            ).register(
                BetaRegistrationInput(
                    display_name=payload.display_name,
                    idempotency_key=idempotency_key,
                ),
                correlation_id=uuid5(NAMESPACE_URL, request.state.request_id),
            )
        return BetaRegistrationResponse(
            registration_id=result.registration_id,
            account_id=result.account_id,
            agent_id=result.agent_id,
            agent_api_key=result.plaintext_api_key,
            credential_scopes=result.scopes,
            mcp_endpoint=settings.public_mcp_endpoint,
            promotional_credit_micro_usd=result.promotional_credit_micro_usd,
            starter_policy=StarterPolicySummary(
                policy_id=result.policy_id,
                version=result.policy_version,
            ),
            quickstart_url=settings.public_quickstart_url or None,
        )
    except BetaRegistrationConflict as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="idempotency conflict"
        ) from exc
    except BetaRegistrationCredentialAlreadyIssued as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="registration completed; credential recovery required",
        ) from exc
    except BetaRegistrationLimitReached as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="beta full"
        ) from exc
    except (BetaRegistrationUnavailable, IntegrityError) as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable"
        ) from exc
    finally:
        session.close()


def _valid_bootstrap_token(candidate: str | None, settings: Settings) -> bool:
    if candidate is None or not settings.beta_registration_bootstrap_token:
        return False
    expected = hashlib.sha256(settings.beta_registration_bootstrap_token.encode()).digest()
    actual = hashlib.sha256(candidate.encode()).digest()
    return hmac.compare_digest(actual, expected)


def _rate_limit(request: Request, dependencies: BetaRouteDependencies) -> None:
    client_host = request.client.host if request.client else "unknown"
    client_hash = hashlib.sha256(client_host.encode()).hexdigest()[:32]
    key = f"outcome:beta-registration-rate:{client_hash}"
    if dependencies.redis is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable")
    try:
        with dependencies.redis.pipeline(transaction=True) as pipeline:
            pipeline.incr(key)
            pipeline.expire(key, dependencies.settings.beta_registration_rate_window_seconds)
            count, expiry_set = pipeline.execute()
    except RedisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable"
        ) from exc
    if not expiry_set:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable")
    if int(count) > dependencies.settings.beta_registration_rate_limit:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limited")
