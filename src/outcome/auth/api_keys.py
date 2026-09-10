from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.db.models import AgentCredential

KEY_PUBLIC_PREFIX = "oc_agent"
SECRET_BYTES = 32
SALT_BYTES = 16
PBKDF2_ITERATIONS = 210_000


class ApiKeyScope(StrEnum):
    VERIFY_WRITE = "verify:write"
    AUTHORIZE_WRITE = "authorize:write"
    RECEIPTS_READ = "receipts:read"
    BILLING_READ = "billing:read"


class ApiKeyAuthError(StrEnum):
    INVALID = "INVALID_API_KEY"
    MALFORMED = "MALFORMED_AUTHORIZATION"
    REVOKED = "REVOKED_API_KEY"
    MISSING_SCOPE = "MISSING_SCOPE"
    WRONG_ACCOUNT = "WRONG_ACCOUNT"


@dataclass(frozen=True)
class AgentApiKey:
    credential_id: UUID
    account_id: UUID
    agent_id: UUID
    scopes: frozenset[ApiKeyScope]


@dataclass(frozen=True)
class AgentApiKeyCreateResult:
    plaintext_key: str
    credential: AgentCredential


class AgentApiKeyAuthenticator:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_development_key(
        self,
        *,
        account_id: UUID,
        agent_id: UUID,
        scopes: set[ApiKeyScope],
    ) -> AgentApiKeyCreateResult:
        secret = secrets.token_hex(SECRET_BYTES)
        key_prefix = secrets.token_hex(8)
        plaintext_key = f"{KEY_PUBLIC_PREFIX}_{key_prefix}_{secret}"
        key_hash = hash_api_key(plaintext_key)

        credential = AgentCredential(
            id=uuid4(),
            account_id=account_id,
            agent_id=agent_id,
            key_fingerprint=fingerprint_api_key(plaintext_key),
            key_ciphertext_ref=None,
            key_prefix=key_prefix,
            key_hash=key_hash,
            scopes=sorted(scope.value for scope in scopes),
            metadata_json={},
        )
        self.session.add(credential)
        self.session.flush()

        return AgentApiKeyCreateResult(plaintext_key=plaintext_key, credential=credential)

    def authenticate(
        self,
        *,
        authorization_header: str | None,
        required_scope: ApiKeyScope,
        account_id: UUID | None = None,
    ) -> AgentApiKey | ApiKeyAuthError:
        parsed_key = parse_bearer_key(authorization_header)
        if parsed_key is None:
            return ApiKeyAuthError.MALFORMED

        key_prefix = extract_key_prefix(parsed_key)
        if key_prefix is None:
            return ApiKeyAuthError.MALFORMED

        credential = self.session.scalar(
            select(AgentCredential).where(AgentCredential.key_prefix == key_prefix)
        )
        if credential is None or not verify_api_key(parsed_key, credential.key_hash):
            return ApiKeyAuthError.INVALID

        if credential.revoked_at is not None or credential.disabled_at is not None:
            return ApiKeyAuthError.REVOKED

        if account_id is not None and credential.account_id != account_id:
            return ApiKeyAuthError.WRONG_ACCOUNT

        credential_scopes = {
            ApiKeyScope(scope)
            for scope in credential.scopes
            if scope in ApiKeyScope._value2member_map_
        }
        if required_scope not in credential_scopes:
            return ApiKeyAuthError.MISSING_SCOPE

        credential.last_used_at = datetime.now(UTC)
        self.session.flush()

        return AgentApiKey(
            credential_id=credential.id,
            account_id=credential.account_id,
            agent_id=credential.agent_id,
            scopes=frozenset(credential_scopes),
        )

    def revoke(self, credential: AgentCredential) -> None:
        credential.revoked_at = datetime.now(UTC)
        self.session.flush()


def parse_bearer_key(authorization_header: str | None) -> str | None:
    if authorization_header is None:
        return None

    scheme, separator, value = authorization_header.partition(" ")
    if separator != " " or scheme != "Bearer" or not value:
        return None

    return value


def extract_key_prefix(plaintext_key: str) -> str | None:
    parts = plaintext_key.split("_")
    if len(parts) != 4 or parts[0] != "oc" or parts[1] != "agent":
        return None
    if not parts[2] or not parts[3]:
        return None
    return parts[2]


def hash_api_key(plaintext_key: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive_key(plaintext_key, salt)
    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}$"
        f"{_encode_token(salt)}${_encode_token(digest)}"
    )


def verify_api_key(plaintext_key: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, encoded_salt, encoded_digest = stored_hash.split("$", maxsplit=3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = _decode_token(encoded_salt)
        expected_digest = _decode_token(encoded_digest)
        candidate_digest = hashlib.pbkdf2_hmac(
            "sha256",
            plaintext_key.encode("utf-8"),
            salt,
            int(iterations),
        )
    except (TypeError, ValueError):
        return False

    return hmac.compare_digest(candidate_digest, expected_digest)


def fingerprint_api_key(plaintext_key: str) -> str:
    return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()


def redact_authorization_header(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "[REDACTED]" if name.lower() == "authorization" else value
        for name, value in headers.items()
    }


def _derive_key(plaintext_key: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        plaintext_key.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )


def _encode_token(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_token(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
