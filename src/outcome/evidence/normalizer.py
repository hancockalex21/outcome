from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import EvidenceItem

MAX_SOURCE_BYTES = 16_384
MAX_NORMALIZED_TEXT_CHARS = 4_096
MAX_JSON_DEPTH = 8
MAX_JSON_FIELDS = 128
EXTRACTION_VERSION = "inert-evidence-v1"
SAFE_URI_SCHEMES = frozenset({"https", "http", "urn", "provider", "evidence"})


class SourceClass(StrEnum):
    PRIMARY = "PRIMARY"
    AUTHORITATIVE_REGISTRY = "AUTHORITATIVE_REGISTRY"
    REPUTABLE_SECONDARY = "REPUTABLE_SECONDARY"
    DERIVATIVE = "DERIVATIVE"
    UNKNOWN = "UNKNOWN"


class ExtractionQuality(StrEnum):
    EXACT_STRUCTURED = "EXACT_STRUCTURED"
    DIRECT_TEXT = "DIRECT_TEXT"
    NORMALIZED_TEXT = "NORMALIZED_TEXT"
    PARTIAL = "PARTIAL"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    FAILED = "FAILED"


class EvidenceNormalizationError(ValueError):
    pass


class UnsafeSourceReference(EvidenceNormalizationError):
    pass


class CrossTenantEvidenceAccess(PermissionError):
    pass


@dataclass(frozen=True)
class EvidenceNormalizationInput:
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID | None
    provider_alias: str | None
    source_uri: str | None
    source_class: SourceClass
    content_type: str
    body: bytes | str
    observed_at: datetime
    authority_metadata: dict[str, object] | None = None
    lineage_metadata: dict[str, object] | None = None


@dataclass(frozen=True)
class InertEvidence:
    evidence_id: UUID
    account_id: UUID
    verification_request_id: UUID
    provider_id: UUID | None
    provider_alias: str | None
    source_uri: str | None
    source_class: SourceClass
    content_type: str
    normalized_text: str
    structured_facts: dict[str, object] | None
    content_hash: str
    observed_at: datetime
    extraction_method: str
    extraction_version: str
    extraction_quality: ExtractionQuality
    authority_metadata: dict[str, object]
    lineage_metadata: dict[str, object]
    size_metadata: dict[str, object]
    truncated: bool
    safety_flags: tuple[str, ...]


class EvidenceNormalizer:
    def __init__(self, session: Session, audit_service: AuditService | None = None) -> None:
        self.session = session
        self.audit_service = audit_service or AuditService(session)

    def normalize(
        self,
        evidence_input: EvidenceNormalizationInput,
        *,
        correlation_id: UUID,
    ) -> InertEvidence:
        try:
            _validate_source_uri(evidence_input.source_uri)
            observed_at = _aware_utc(evidence_input.observed_at)
            source_bytes = _coerce_bytes(evidence_input.body)
            if len(source_bytes) > MAX_SOURCE_BYTES:
                raise EvidenceNormalizationError("source payload exceeds maximum accepted size")
            normalized = self._normalize_content(evidence_input.content_type, source_bytes)
            inert = InertEvidence(
                evidence_id=uuid4(),
                account_id=evidence_input.account_id,
                verification_request_id=evidence_input.verification_request_id,
                provider_id=evidence_input.provider_id,
                provider_alias=evidence_input.provider_alias,
                source_uri=evidence_input.source_uri,
                source_class=evidence_input.source_class,
                content_type=_canonical_content_type(evidence_input.content_type),
                normalized_text=normalized.text,
                structured_facts=normalized.structured_facts,
                content_hash=_content_hash(
                    normalized_text=normalized.text,
                    structured_facts=normalized.structured_facts,
                    content_type=_canonical_content_type(evidence_input.content_type),
                ),
                observed_at=observed_at,
                extraction_method=normalized.method,
                extraction_version=EXTRACTION_VERSION,
                extraction_quality=normalized.quality,
                authority_metadata=evidence_input.authority_metadata or {},
                lineage_metadata=evidence_input.lineage_metadata or {},
                size_metadata={
                    "source_bytes": len(source_bytes),
                    "normalized_characters": len(normalized.text),
                    "structured_field_count": normalized.field_count,
                },
                truncated=normalized.truncated,
                safety_flags=tuple(normalized.safety_flags),
            )
            self._persist(inert)
            self._audit_acceptance(inert=inert, correlation_id=correlation_id)
            if inert.truncated:
                self._audit(
                    inert=inert,
                    event_type=AuditEventType.EVIDENCE_TRUNCATED,
                    correlation_id=correlation_id,
                    reason_code="EVIDENCE_TRUNCATED",
                )
            return inert
        except UnsafeSourceReference:
            self._audit_rejection(
                evidence_input=evidence_input,
                event_type=AuditEventType.EVIDENCE_UNSAFE_SOURCE_REJECTED,
                correlation_id=correlation_id,
                reason_code="UNSAFE_SOURCE_REFERENCE",
            )
            raise
        except EvidenceNormalizationError:
            self._audit_rejection(
                evidence_input=evidence_input,
                event_type=AuditEventType.EVIDENCE_NORMALIZATION_REJECTED,
                correlation_id=correlation_id,
                reason_code="EVIDENCE_NORMALIZATION_REJECTED",
            )
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._audit_rejection(
                evidence_input=evidence_input,
                event_type=AuditEventType.EVIDENCE_EXTRACTION_FAILED,
                correlation_id=correlation_id,
                reason_code="EVIDENCE_EXTRACTION_FAILED",
            )
            raise EvidenceNormalizationError("evidence extraction failed") from exc

    def get(self, *, account_id: UUID, evidence_id: UUID) -> InertEvidence | None:
        item = self.session.scalar(
            select(EvidenceItem).where(
                EvidenceItem.account_id == account_id,
                EvidenceItem.id == evidence_id,
            )
        )
        if item is not None:
            return _from_model(item)
        cross_tenant = self.session.scalar(
            select(EvidenceItem).where(EvidenceItem.id == evidence_id)
        )
        if cross_tenant is not None:
            raise CrossTenantEvidenceAccess("evidence belongs to a different account")
        return None

    def _normalize_content(self, content_type: str, source_bytes: bytes) -> _NormalizedEvidence:
        canonical = _canonical_content_type(content_type)
        if canonical == "text/plain":
            text = _decode_text(source_bytes)
            text, truncated = _truncate_text(_normalize_whitespace(text))
            return _NormalizedEvidence(
                text=text,
                structured_facts=None,
                method="plain_text",
                quality=(
                    ExtractionQuality.DIRECT_TEXT
                    if not truncated
                    else ExtractionQuality.PARTIAL
                ),
                truncated=truncated,
                field_count=0,
                safety_flags=["HOSTILE_EXTERNAL_CONTENT"],
            )
        if canonical == "text/html":
            parser = _InertHTMLTextExtractor()
            parser.feed(_decode_text(source_bytes))
            text, truncated = _truncate_text(_normalize_whitespace(parser.text()))
            return _NormalizedEvidence(
                text=text,
                structured_facts=None,
                method="html_text_extraction",
                quality=ExtractionQuality.NORMALIZED_TEXT
                if not truncated
                else ExtractionQuality.PARTIAL,
                truncated=truncated,
                field_count=0,
                safety_flags=["HOSTILE_EXTERNAL_CONTENT", "HTML_STRIPPED"],
            )
        if canonical == "application/json":
            parsed = json.loads(_decode_text(source_bytes))
            normalized, field_count = _normalize_json(parsed)
            text = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            text, truncated = _truncate_text(text)
            return _NormalizedEvidence(
                text=text,
                structured_facts=(
                    normalized if isinstance(normalized, dict) else {"value": normalized}
                ),
                method="json_data_normalization",
                quality=ExtractionQuality.EXACT_STRUCTURED
                if not truncated
                else ExtractionQuality.PARTIAL,
                truncated=truncated,
                field_count=field_count,
                safety_flags=["HOSTILE_EXTERNAL_CONTENT", "JSON_AS_DATA"],
            )
        raise EvidenceNormalizationError(f"unsupported content type: {content_type}")

    def _persist(self, inert: InertEvidence) -> None:
        self.session.add(
            EvidenceItem(
                id=inert.evidence_id,
                account_id=inert.account_id,
                verification_request_id=inert.verification_request_id,
                evidence_type=inert.content_type,
                evidence_hash=inert.content_hash,
                evidence_ref=inert.source_uri,
                provider_id=inert.provider_id,
                provider_alias=inert.provider_alias,
                source_uri=inert.source_uri,
                source_class=inert.source_class.value,
                content_type=inert.content_type,
                normalized_text=inert.normalized_text,
                extraction_method=inert.extraction_method,
                extraction_version=inert.extraction_version,
                extraction_quality=inert.extraction_quality.value,
                authority_metadata=inert.authority_metadata,
                lineage_metadata=inert.lineage_metadata,
                size_metadata=inert.size_metadata,
                safety_flags=list(inert.safety_flags),
                observed_at=inert.observed_at,
                truncated=inert.truncated,
            )
        )
        self.session.flush()

    def _audit_acceptance(self, *, inert: InertEvidence, correlation_id: UUID) -> None:
        self._audit(
            inert=inert,
            event_type=AuditEventType.EVIDENCE_NORMALIZATION_ACCEPTED,
            correlation_id=correlation_id,
            reason_code="EVIDENCE_NORMALIZATION_ACCEPTED",
        )

    def _audit(
        self,
        *,
        inert: InertEvidence,
        event_type: AuditEventType,
        correlation_id: UUID,
        reason_code: str,
    ) -> None:
        self.audit_service.append_event(
            account_id=inert.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=inert.verification_request_id,
            payload={
                "evidence_id": inert.evidence_id,
                "provider_id": inert.provider_id,
                "provider_alias": inert.provider_alias,
                "source_class": inert.source_class.value,
                "extraction_quality": inert.extraction_quality.value,
                "content_hash": inert.content_hash,
                "byte_count": inert.size_metadata["source_bytes"],
                "character_count": inert.size_metadata["normalized_characters"],
                "truncated": inert.truncated,
                "reason_codes": [reason_code],
            },
        )

    def _audit_rejection(
        self,
        *,
        evidence_input: EvidenceNormalizationInput,
        event_type: AuditEventType,
        correlation_id: UUID,
        reason_code: str,
    ) -> None:
        self.audit_service.append_event(
            account_id=evidence_input.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            request_id=evidence_input.verification_request_id,
            payload={
                "provider_id": evidence_input.provider_id,
                "provider_alias": evidence_input.provider_alias,
                "source_class": evidence_input.source_class.value,
                "reason_codes": [reason_code],
            },
        )


@dataclass(frozen=True)
class _NormalizedEvidence:
    text: str
    structured_facts: dict[str, object] | None
    method: str
    quality: ExtractionQuality
    truncated: bool
    field_count: int
    safety_flags: list[str]


class _InertHTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "template", "noscript"}:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "template", "noscript"} and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return " ".join(self._parts)


def _validate_source_uri(source_uri: str | None) -> None:
    if source_uri is None:
        return
    if source_uri.startswith(("/", "./", "../")):
        raise UnsafeSourceReference("local filesystem source references are not allowed")
    parsed = urlparse(source_uri)
    if parsed.scheme.lower() not in SAFE_URI_SCHEMES:
        raise UnsafeSourceReference("unsupported or unsafe source URI scheme")


def _coerce_bytes(body: bytes | str) -> bytes:
    return body if isinstance(body, bytes) else body.encode("utf-8")


def _decode_text(source_bytes: bytes) -> str:
    return source_bytes.decode("utf-8", errors="strict")


def _canonical_content_type(content_type: str) -> str:
    return content_type.split(";", 1)[0].strip().lower()


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _truncate_text(text: str) -> tuple[str, bool]:
    if len(text) <= MAX_NORMALIZED_TEXT_CHARS:
        return text, False
    return text[:MAX_NORMALIZED_TEXT_CHARS], True


def _normalize_json(
    value: object,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
) -> tuple[Any, int]:
    if counter is None:
        counter = [0]
    if depth > MAX_JSON_DEPTH:
        raise EvidenceNormalizationError("JSON nesting exceeds maximum depth")
    if value is None or isinstance(value, str | bool):
        return value, counter[0]
    if isinstance(value, int):
        return value, counter[0]
    if isinstance(value, float):
        raise EvidenceNormalizationError("floating-point JSON values are not accepted")
    if isinstance(value, list):
        return (
            [_normalize_json(item, depth=depth + 1, counter=counter)[0] for item in value],
            counter[0],
        )
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise EvidenceNormalizationError("JSON object keys must be strings")
            counter[0] += 1
            if counter[0] > MAX_JSON_FIELDS:
                raise EvidenceNormalizationError("JSON field count exceeds maximum")
            normalized[key] = _normalize_json(value[key], depth=depth + 1, counter=counter)[0]
        return normalized, counter[0]
    raise EvidenceNormalizationError(f"unsupported JSON value type: {type(value).__name__}")


def _content_hash(
    *,
    normalized_text: str,
    structured_facts: dict[str, object] | None,
    content_type: str,
) -> str:
    payload = {
        "content_type": content_type,
        "normalized_text": normalized_text,
        "structured_facts": structured_facts,
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceNormalizationError("evidence timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _from_model(item: EvidenceItem) -> InertEvidence:
    return InertEvidence(
        evidence_id=item.id,
        account_id=item.account_id,
        verification_request_id=item.verification_request_id,
        provider_id=item.provider_id,
        provider_alias=item.provider_alias,
        source_uri=item.source_uri,
        source_class=SourceClass(item.source_class),
        content_type=item.content_type,
        normalized_text=item.normalized_text,
        structured_facts=None,
        content_hash=item.evidence_hash,
        observed_at=item.observed_at,
        extraction_method=item.extraction_method,
        extraction_version=item.extraction_version,
        extraction_quality=ExtractionQuality(item.extraction_quality),
        authority_metadata=item.authority_metadata,
        lineage_metadata=item.lineage_metadata,
        size_metadata=item.size_metadata,
        truncated=item.truncated,
        safety_flags=tuple(str(flag) for flag in item.safety_flags),
    )
