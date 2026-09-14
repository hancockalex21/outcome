from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from outcome.audit import AuditEventType, AuditService
from outcome.db.models import CustomerProviderCredential
from outcome.pricing import BillingMode, CapabilityName
from outcome.providers import (
    ProviderCredentialMode,
    ProviderDataUse,
    ProviderExecutionMode,
    ProviderRightsRequest,
    ProviderRightsService,
)
from outcome.secrets import CredentialLifecycleState, CredentialType, SecretReference


class SecretResolutionStatus(StrEnum):
    SECRET_RESOLVED = "SECRET_RESOLVED"
    SECRET_NOT_FOUND = "SECRET_NOT_FOUND"
    SECRET_REVOKED = "SECRET_REVOKED"
    SECRET_DISABLED = "SECRET_DISABLED"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    PROVIDER_MISMATCH = "PROVIDER_MISMATCH"
    RIGHTS_DENIED = "RIGHTS_DENIED"
    SECRET_STORE_FAILURE = "SECRET_STORE_FAILURE"


@dataclass(frozen=True)
class WorkerProviderExecutionRequest:
    account_id: UUID
    provider_id: UUID
    capability: CapabilityName
    secret_ref: str
    requested_region: str
    requested_data_use: ProviderDataUse
    requested_execution_mode: ProviderExecutionMode
    request_metadata: Mapping[str, object]
    action_reference_id: UUID | None = None
    verification_reference_id: UUID | None = None
    evaluated_at: datetime | None = None


class SecretMaterial:
    __slots__ = ("_value", "credential_type")

    def __init__(self, value: str, *, credential_type: CredentialType) -> None:
        if not value:
            raise ValueError("secret material cannot be empty")
        self._value = value
        self.credential_type = credential_type

    def reveal_for_provider_call(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretMaterial([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"


@dataclass(frozen=True)
class SecretResolutionResult:
    status: SecretResolutionStatus
    secret_ref: str
    account_id: UUID
    provider_id: UUID
    credential_type: CredentialType | None = None
    credential_version: str | None = None
    material: SecretMaterial | None = None
    reason_code: str | None = None


class DevelopmentSecretStore:
    def put(self, *, secret_ref: str, secret_value: str) -> None:
        raise NotImplementedError

    def get(self, *, secret_ref: str) -> str | None:
        raise NotImplementedError


class InMemoryDevelopmentSecretStore(DevelopmentSecretStore):
    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self.fail_reads = False

    def put(self, *, secret_ref: str, secret_value: str) -> None:
        self._secrets[secret_ref] = secret_value

    def get(self, *, secret_ref: str) -> str | None:
        if self.fail_reads:
            raise RuntimeError("development secret store read failed")
        return self._secrets.get(secret_ref)


class SecretResolver(Protocol):
    def resolve(self, *, secret_ref: str, account_id: UUID, provider_id: UUID) -> SecretMaterial:
        raise NotImplementedError


class DevelopmentSecretResolver:
    def __init__(self, *, store: DevelopmentSecretStore, session: Session) -> None:
        self.store = store
        self.session = session

    def resolve(self, *, secret_ref: str, account_id: UUID, provider_id: UUID) -> SecretMaterial:
        credential = self.session.scalar(
            select(CustomerProviderCredential).where(
                CustomerProviderCredential.secret_ref == secret_ref,
                CustomerProviderCredential.account_id == account_id,
                CustomerProviderCredential.provider_id == provider_id,
            )
        )
        if credential is None:
            raise SecretLookupError("secret reference not found")
        value = self.store.get(secret_ref=secret_ref)
        if value is None:
            raise SecretLookupError("secret material not found")
        return SecretMaterial(value, credential_type=CredentialType(credential.credential_type))


class SecretLookupError(RuntimeError):
    pass


class WorkerSecretResolutionService:
    def __init__(
        self,
        session: Session,
        *,
        resolver: SecretResolver,
        provider_rights_service: ProviderRightsService,
        audit_service: AuditService | None = None,
    ) -> None:
        self.session = session
        self.resolver = resolver
        self.provider_rights_service = provider_rights_service
        self.audit_service = audit_service or AuditService(session)

    def resolve_for_execution(
        self,
        request: WorkerProviderExecutionRequest,
        *,
        correlation_id: UUID,
    ) -> SecretResolutionResult:
        credential = self._find_by_ref(secret_ref=request.secret_ref)
        if credential is None:
            result = self._result(
                status=SecretResolutionStatus.SECRET_NOT_FOUND,
                request=request,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result

        if credential.account_id != request.account_id:
            result = self._result(
                status=SecretResolutionStatus.TENANT_MISMATCH,
                request=request,
                credential=credential,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result
        if credential.provider_id != request.provider_id:
            result = self._result(
                status=SecretResolutionStatus.PROVIDER_MISMATCH,
                request=request,
                credential=credential,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result

        metadata_ref = self._to_secret_reference(credential)
        self._audit_selected(secret_reference=metadata_ref, correlation_id=correlation_id)

        rights = self.provider_rights_service.authorize(
            ProviderRightsRequest(
                account_id=request.account_id,
                provider_id=request.provider_id,
                capability=request.capability,
                billing_mode=BillingMode.BYOK,
                requested_region=request.requested_region,
                requested_data_use=request.requested_data_use,
                requested_execution_mode=request.requested_execution_mode,
                credential_mode=ProviderCredentialMode.CUSTOMER_MANAGED,
                evaluated_at=request.evaluated_at,
            ),
            correlation_id=correlation_id,
        )
        if not rights.allowed:
            result = self._result(
                status=SecretResolutionStatus.RIGHTS_DENIED,
                request=request,
                credential=credential,
                reason_code=rights.reason_code.value,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result

        state = CredentialLifecycleState(credential.lifecycle_state)
        if state is not CredentialLifecycleState.ACTIVE:
            result = self._inactive_result(request=request, credential=credential, state=state)
            self._audit(result=result, correlation_id=correlation_id)
            return result

        self._audit_attempt(request=request, credential=credential, correlation_id=correlation_id)
        try:
            material = self.resolver.resolve(
                secret_ref=request.secret_ref,
                account_id=request.account_id,
                provider_id=request.provider_id,
            )
        except (SecretLookupError, SQLAlchemyError):
            result = self._result(
                status=SecretResolutionStatus.SECRET_NOT_FOUND,
                request=request,
                credential=credential,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result
        except Exception:
            result = self._result(
                status=SecretResolutionStatus.SECRET_STORE_FAILURE,
                request=request,
                credential=credential,
            )
            self._audit(result=result, correlation_id=correlation_id)
            return result

        result = self._result(
            status=SecretResolutionStatus.SECRET_RESOLVED,
            request=request,
            credential=credential,
            material=material,
        )
        self._audit(result=result, correlation_id=correlation_id)
        return result

    def _find_by_ref(self, *, secret_ref: str) -> CustomerProviderCredential | None:
        return self.session.scalar(
            select(CustomerProviderCredential).where(
                CustomerProviderCredential.secret_ref == secret_ref
            )
        )

    def _inactive_result(
        self,
        *,
        request: WorkerProviderExecutionRequest,
        credential: CustomerProviderCredential,
        state: CredentialLifecycleState,
    ) -> SecretResolutionResult:
        status = {
            CredentialLifecycleState.REVOKED: SecretResolutionStatus.SECRET_REVOKED,
            CredentialLifecycleState.DISABLED: SecretResolutionStatus.SECRET_DISABLED,
            CredentialLifecycleState.ROTATED: SecretResolutionStatus.SECRET_REVOKED,
        }[state]
        return self._result(status=status, request=request, credential=credential)

    def _result(
        self,
        *,
        status: SecretResolutionStatus,
        request: WorkerProviderExecutionRequest,
        credential: CustomerProviderCredential | None = None,
        material: SecretMaterial | None = None,
        reason_code: str | None = None,
    ) -> SecretResolutionResult:
        return SecretResolutionResult(
            status=status,
            secret_ref=request.secret_ref,
            account_id=request.account_id,
            provider_id=request.provider_id,
            credential_type=(
                CredentialType(credential.credential_type) if credential is not None else None
            ),
            credential_version=credential.version if credential is not None else None,
            material=material,
            reason_code=reason_code or status.value,
        )

    def _to_secret_reference(self, credential: CustomerProviderCredential) -> SecretReference:
        return SecretReference(
            secret_ref=credential.secret_ref,
            account_id=credential.account_id,
            provider_id=credential.provider_id,
            credential_type=CredentialType(credential.credential_type),
            created_at=credential.created_at,
            lifecycle_state=CredentialLifecycleState(credential.lifecycle_state),
            version=credential.version,
            rotated_at=credential.rotated_at,
            metadata=credential.metadata_json,
        )

    def _audit_selected(
        self,
        *,
        secret_reference: SecretReference,
        correlation_id: UUID,
    ) -> None:
        self.audit_service.append_event(
            account_id=secret_reference.account_id,
            event_type=AuditEventType.SECRET_REFERENCE_SELECTED,
            correlation_id=correlation_id,
            payload={
                "secret_ref": secret_reference.secret_ref,
                "provider_id": secret_reference.provider_id,
                "credential_type": secret_reference.credential_type.value,
                "credential_state": secret_reference.lifecycle_state.value,
                "credential_version": secret_reference.version,
                "reason_codes": ["SECRET_REFERENCE_SELECTED"],
            },
        )

    def _audit_attempt(
        self,
        *,
        request: WorkerProviderExecutionRequest,
        credential: CustomerProviderCredential,
        correlation_id: UUID,
    ) -> None:
        self.audit_service.append_event(
            account_id=request.account_id,
            event_type=AuditEventType.SECRET_RESOLUTION_ATTEMPTED,
            correlation_id=correlation_id,
            payload={
                "secret_ref": request.secret_ref,
                "provider_id": request.provider_id,
                "credential_type": credential.credential_type,
                "credential_state": credential.lifecycle_state,
                "credential_version": credential.version,
                "reason_codes": ["SECRET_RESOLUTION_ATTEMPTED"],
            },
        )

    def _audit(self, *, result: SecretResolutionResult, correlation_id: UUID) -> None:
        event_type = {
            SecretResolutionStatus.SECRET_RESOLVED: AuditEventType.SECRET_RESOLUTION_SUCCEEDED,
            SecretResolutionStatus.SECRET_REVOKED: AuditEventType.SECRET_CREDENTIAL_INACTIVE,
            SecretResolutionStatus.SECRET_DISABLED: AuditEventType.SECRET_CREDENTIAL_INACTIVE,
        }.get(result.status, AuditEventType.SECRET_RESOLUTION_DENIED)
        self.audit_service.append_event(
            account_id=result.account_id,
            event_type=event_type,
            correlation_id=correlation_id,
            payload={
                "secret_ref": result.secret_ref,
                "provider_id": result.provider_id,
                "credential_type": result.credential_type.value if result.credential_type else None,
                "credential_version": result.credential_version,
                "secret_resolution_status": result.status.value,
                "reason_codes": [result.reason_code or result.status.value],
            },
        )
