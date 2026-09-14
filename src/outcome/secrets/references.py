from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class CredentialLifecycleState(StrEnum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    DISABLED = "DISABLED"


class CredentialType(StrEnum):
    API_KEY = "API_KEY"
    BEARER_TOKEN = "BEARER_TOKEN"
    OAUTH_CLIENT = "OAUTH_CLIENT"


@dataclass(frozen=True)
class SecretReference:
    secret_ref: str
    account_id: UUID
    provider_id: UUID
    credential_type: CredentialType
    created_at: datetime
    lifecycle_state: CredentialLifecycleState
    version: str
    rotated_at: datetime | None = None
    metadata: dict[str, object] | None = None

    def __post_init__(self) -> None:
        if not self.secret_ref:
            raise ValueError("secret_ref is required")
        if self.secret_ref.startswith(("sk-", "pk_", "Bearer ")):
            raise ValueError("secret_ref must be opaque metadata, not credential material")
        if not self.version:
            raise ValueError("secret reference version is required")
