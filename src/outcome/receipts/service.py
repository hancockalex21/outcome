from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.actions import CanonicalizationError, normalize_utc_timestamp
from outcome.audit import AuditEventType, AuditService
from outcome.db.models import Receipt
from outcome.domain import PolicyDecision, VerificationStatus

RECEIPT_VERSION = "outcome.authorization.receipt.v1"
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MIN_SAFE_JSON_INTEGER = -MAX_SAFE_JSON_INTEGER


class ReceiptError(ValueError):
    pass


class ReceiptMalformed(ReceiptError):
    pass


class CrossTenantReceiptAccess(PermissionError):
    pass


class ReceiptVerificationStatus(StrEnum):
    SIGNATURE_VALID = "SIGNATURE_VALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    RECEIPT_EXPIRED = "RECEIPT_EXPIRED"
    RECEIPT_MALFORMED = "RECEIPT_MALFORMED"
    UNKNOWN_SIGNING_KEY = "UNKNOWN_SIGNING_KEY"


@dataclass(frozen=True)
class ReceiptPayload:
    receipt_version: str
    receipt_id: UUID
    account_id: UUID
    authorization_request_id: UUID
    action_hash: str
    action_schema_version: str
    policy_version: str
    policy_decision: PolicyDecision
    verification_status: VerificationStatus | None
    issued_at: datetime
    expires_at: datetime
    signing_key_id: str

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "receipt_version": _nonempty_string(self.receipt_version, "receipt_version"),
            "receipt_id": str(self.receipt_id),
            "account_id": str(self.account_id),
            "authorization_request_id": str(self.authorization_request_id),
            "action_hash": _nonempty_string(self.action_hash, "action_hash"),
            "action_schema_version": _nonempty_string(
                self.action_schema_version,
                "action_schema_version",
            ),
            "policy_version": _nonempty_string(self.policy_version, "policy_version"),
            "policy_decision": self.policy_decision.value,
            "issued_at": normalize_utc_timestamp(self.issued_at),
            "expires_at": normalize_utc_timestamp(self.expires_at),
            "signing_key_id": _nonempty_string(self.signing_key_id, "signing_key_id"),
        }
        if self.verification_status is not None:
            payload["verification_status"] = self.verification_status.value
        return payload


@dataclass(frozen=True)
class SignedReceipt:
    payload: ReceiptPayload
    signature: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "payload": self.payload.to_public_dict(),
            "signature": self.signature,
        }


@dataclass(frozen=True)
class ReceiptVerificationResult:
    status: ReceiptVerificationStatus
    signature_valid: bool
    currently_executable: bool
    payload: ReceiptPayload | None = None


class ReceiptSigner(Protocol):
    signing_key_id: str

    def sign(self, payload: ReceiptPayload) -> SignedReceipt:
        raise NotImplementedError


class ReceiptVerifier(Protocol):
    def verify(
        self,
        signed_receipt: SignedReceipt,
        *,
        now: datetime | None = None,
    ) -> ReceiptVerificationResult:
        raise NotImplementedError


class Ed25519ReceiptSigner:
    def __init__(self, *, signing_key_id: str, private_key: Ed25519PrivateKey) -> None:
        self.signing_key_id = _nonempty_string(signing_key_id, "signing_key_id")
        self._private_key = private_key

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        signing_key_id: str,
        private_key_bytes: bytes,
    ) -> Ed25519ReceiptSigner:
        return cls(
            signing_key_id=signing_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key_bytes),
        )

    def sign(self, payload: ReceiptPayload) -> SignedReceipt:
        if payload.signing_key_id != self.signing_key_id:
            payload = replace(payload, signing_key_id=self.signing_key_id)
        signature = self._private_key.sign(canonical_receipt_bytes(payload))
        return SignedReceipt(
            payload=payload,
            signature=base64.urlsafe_b64encode(signature).decode("ascii"),
        )

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )


class Ed25519ReceiptVerifier:
    def __init__(self, public_keys: Mapping[str, Ed25519PublicKey | bytes]) -> None:
        self._public_keys = {
            _nonempty_string(key_id, "signing_key_id"): (
                Ed25519PublicKey.from_public_bytes(public_key)
                if isinstance(public_key, bytes)
                else public_key
            )
            for key_id, public_key in public_keys.items()
        }

    def verify(
        self,
        signed_receipt: SignedReceipt,
        *,
        now: datetime | None = None,
    ) -> ReceiptVerificationResult:
        try:
            payload = signed_receipt.payload
            public_key = self._public_keys.get(payload.signing_key_id)
            if public_key is None:
                return ReceiptVerificationResult(
                    status=ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY,
                    signature_valid=False,
                    currently_executable=False,
                    payload=payload,
                )
            signature = base64.urlsafe_b64decode(signed_receipt.signature.encode("ascii"))
            public_key.verify(signature, canonical_receipt_bytes(payload))
        except (CanonicalizationError, ValueError, TypeError):
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.RECEIPT_MALFORMED,
                signature_valid=False,
                currently_executable=False,
            )
        except InvalidSignature:
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.SIGNATURE_INVALID,
                signature_valid=False,
                currently_executable=False,
                payload=signed_receipt.payload,
            )

        verification_time = _verification_time(now)
        if verification_time >= signed_receipt.payload.expires_at.astimezone(UTC):
            return ReceiptVerificationResult(
                status=ReceiptVerificationStatus.RECEIPT_EXPIRED,
                signature_valid=True,
                currently_executable=False,
                payload=signed_receipt.payload,
            )

        return ReceiptVerificationResult(
            status=ReceiptVerificationStatus.SIGNATURE_VALID,
            signature_valid=True,
            currently_executable=(
                signed_receipt.payload.policy_decision is PolicyDecision.ALLOW
            ),
            payload=signed_receipt.payload,
        )


class ReceiptService:
    def __init__(
        self,
        session: Session,
        *,
        signer: ReceiptSigner,
        verifier: ReceiptVerifier,
        audit_service: AuditService | None = None,
    ) -> None:
        self.session = session
        self.signer = signer
        self.verifier = verifier
        self.audit_service = audit_service or AuditService(session)

    def issue_authorization_receipt(
        self,
        *,
        account_id: UUID,
        authorization_request_id: UUID,
        action_hash: str,
        action_schema_version: str,
        policy_version: str,
        policy_decision: PolicyDecision,
        expires_at: datetime,
        correlation_id: UUID,
        authorization_result_id: UUID | None = None,
        verification_status: VerificationStatus | None = None,
        issued_at: datetime | None = None,
        receipt_id: UUID | None = None,
    ) -> SignedReceipt:
        issued = _verification_time(issued_at)
        payload = ReceiptPayload(
            receipt_version=RECEIPT_VERSION,
            receipt_id=receipt_id or uuid4(),
            account_id=account_id,
            authorization_request_id=authorization_request_id,
            action_hash=action_hash,
            action_schema_version=action_schema_version,
            policy_version=policy_version,
            policy_decision=policy_decision,
            verification_status=verification_status,
            issued_at=issued,
            expires_at=expires_at,
            signing_key_id=self.signer.signing_key_id,
        )
        signed = self.signer.sign(payload)
        canonical = canonical_receipt_json(signed.payload)

        self.session.add(
            Receipt(
                id=uuid4(),
                account_id=account_id,
                receipt_id=signed.payload.receipt_id,
                verification_result_id=None,
                authorization_result_id=authorization_result_id,
                authorization_request_id=authorization_request_id,
                receipt_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                canonical_payload=signed.payload.to_public_dict(),
                action_hash=action_hash,
                signature=signed.signature,
                signing_key_id=signed.payload.signing_key_id,
                issued_at=issued,
                expires_at=signed.payload.expires_at,
            )
        )
        self.session.flush()
        self.audit_service.append_event(
            account_id=account_id,
            event_type=AuditEventType.RECEIPT_ISSUED,
            correlation_id=correlation_id,
            request_id=authorization_request_id,
            payload={
                "receipt_id": signed.payload.receipt_id,
                "authorization_request_id": authorization_request_id,
                "authorization_result_id": authorization_result_id,
                "action_hash": signed.payload.action_hash,
                "policy_decision": signed.payload.policy_decision,
                "receipt_version": signed.payload.receipt_version,
                "signing_key_id": signed.payload.signing_key_id,
            },
        )
        return signed

    def get(self, *, account_id: UUID, receipt_id: UUID) -> SignedReceipt | None:
        receipt = self.session.scalar(
            select(Receipt).where(
                Receipt.account_id == account_id,
                Receipt.receipt_id == receipt_id,
            )
        )
        if receipt is not None:
            return _signed_receipt_from_model(receipt)

        cross_tenant_receipt = self.session.scalar(
            select(Receipt).where(Receipt.receipt_id == receipt_id)
        )
        if cross_tenant_receipt is not None:
            raise CrossTenantReceiptAccess("receipt belongs to a different account")
        return None

    def verify(
        self,
        *,
        signed_receipt: SignedReceipt,
        account_id: UUID,
        correlation_id: UUID,
        now: datetime | None = None,
    ) -> ReceiptVerificationResult:
        if signed_receipt.payload.account_id != account_id:
            result = ReceiptVerificationResult(
                status=ReceiptVerificationStatus.SIGNATURE_INVALID,
                signature_valid=False,
                currently_executable=False,
                payload=signed_receipt.payload,
            )
        else:
            result = self.verifier.verify(signed_receipt, now=now)
        self._audit_verification(
            account_id=account_id,
            correlation_id=correlation_id,
            signed_receipt=signed_receipt,
            result=result,
        )
        return result

    def _audit_verification(
        self,
        *,
        account_id: UUID,
        correlation_id: UUID,
        signed_receipt: SignedReceipt,
        result: ReceiptVerificationResult,
    ) -> None:
        event_type = {
            ReceiptVerificationStatus.SIGNATURE_VALID: (
                AuditEventType.RECEIPT_VERIFICATION_SUCCEEDED
            ),
            ReceiptVerificationStatus.RECEIPT_EXPIRED: AuditEventType.EXPIRED_RECEIPT_PRESENTED,
            ReceiptVerificationStatus.UNKNOWN_SIGNING_KEY: AuditEventType.UNKNOWN_SIGNING_KEY,
        }.get(result.status, AuditEventType.RECEIPT_VERIFICATION_FAILED)
        self.audit_service.append_event(
            account_id=account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=signed_receipt.payload.authorization_request_id,
            payload={
                "receipt_id": signed_receipt.payload.receipt_id,
                "action_hash": signed_receipt.payload.action_hash,
                "receipt_verification_status": result.status.value,
                "signing_key_id": signed_receipt.payload.signing_key_id,
            },
        )


def canonical_receipt_json(payload: ReceiptPayload) -> str:
    return json.dumps(
        _normalize_receipt_value(payload.to_public_dict()),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_receipt_bytes(payload: ReceiptPayload) -> bytes:
    return canonical_receipt_json(payload).encode("utf-8")


def _signed_receipt_from_model(receipt: Receipt) -> SignedReceipt:
    payload = receipt.canonical_payload
    try:
        verification_status_value = payload.get("verification_status")
        verification_status = (
            None
            if verification_status_value is None
            else VerificationStatus(str(verification_status_value))
        )
        return SignedReceipt(
            payload=ReceiptPayload(
                receipt_version=str(payload["receipt_version"]),
                receipt_id=UUID(str(payload["receipt_id"])),
                account_id=UUID(str(payload["account_id"])),
                authorization_request_id=UUID(str(payload["authorization_request_id"])),
                action_hash=str(payload["action_hash"]),
                action_schema_version=str(payload["action_schema_version"]),
                policy_version=str(payload["policy_version"]),
                policy_decision=PolicyDecision(str(payload["policy_decision"])),
                verification_status=verification_status,
                issued_at=datetime.fromisoformat(str(payload["issued_at"]).replace("Z", "+00:00")),
                expires_at=datetime.fromisoformat(
                    str(payload["expires_at"]).replace("Z", "+00:00")
                ),
                signing_key_id=str(payload["signing_key_id"]),
            ),
            signature=receipt.signature,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ReceiptMalformed("persisted receipt payload is malformed") from exc


def _normalize_receipt_value(value: object) -> object:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_SAFE_JSON_INTEGER <= value <= MAX_SAFE_JSON_INTEGER:
            raise CanonicalizationError("integer is outside the safe canonical JSON range")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating-point receipt values are not accepted")
    if isinstance(value, list):
        return [_normalize_receipt_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("receipt object keys must be strings")
            normalized[key] = _normalize_receipt_value(nested_value)
        return normalized
    raise CanonicalizationError(f"unsupported receipt value type: {type(value).__name__}")


def _nonempty_string(value: str, field_name: str) -> str:
    if not value:
        raise CanonicalizationError(f"{field_name} is required")
    return value


def _verification_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    normalize_utc_timestamp(value)
    return value.astimezone(UTC)
