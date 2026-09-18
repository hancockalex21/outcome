from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from outcome.api.main import _bounded_request_id
from outcome.core.config import ConfigValidationError, Settings, validate_startup_config


def test_production_rejects_unsafe_mcp_defaults() -> None:
    settings = Settings(
        env="production",
        mcp_database_url="sqlite:///local.db",
        mcp_receipt_signing_key_id="outcome-mcp-dev-key",
        mcp_receipt_private_key_b64="",
    )

    with pytest.raises(ConfigValidationError) as exc:
        validate_startup_config(settings, process_role="mcp")

    message = str(exc.value)
    assert "development key" in message
    assert "PRIVATE_KEY" in message
    assert "SQLite" in message


def test_production_rejects_wildcard_cors_and_bad_reservation_ttl() -> None:
    settings = Settings(
        env="production",
        allowed_cors_origins=("*",),
        reservation_ttl_seconds=700,
        max_billable_execution_window_seconds=650,
        reservation_ttl_safety_margin_seconds=120,
    )

    with pytest.raises(ConfigValidationError) as exc:
        validate_startup_config(settings, process_role="api")

    message = str(exc.value)
    assert "wildcard CORS" in message
    assert "billable execution window" in message


def test_production_config_accepts_safe_controlled_beta_settings() -> None:
    private_key = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    settings = Settings(
        env="production",
        database_url="postgresql+asyncpg://outcome@postgres:5432/outcome",
        mcp_database_url="postgresql+psycopg://outcome@postgres:5432/outcome",
        redis_url="redis://redis:6379/0",
        mcp_receipt_signing_key_id="outcome-controlled-beta-key-1",
        mcp_receipt_private_key_b64=base64.urlsafe_b64encode(private_key).decode("ascii"),
        worker_secret_resolver_backend="external-reference",
        reservation_ttl_seconds=900,
        max_billable_execution_window_seconds=600,
        reservation_ttl_safety_margin_seconds=120,
    )

    validate_startup_config(settings, process_role="api")
    validate_startup_config(settings, process_role="mcp")
    validate_startup_config(settings, process_role="worker")


def test_request_id_is_bounded_and_sanitized() -> None:
    assert _bounded_request_id("safe-id_123") == "safe-id_123"
    assert _bounded_request_id("bad\nid") != "bad\nid"
    assert _bounded_request_id("x" * 129) != "x" * 129


def test_api_mcp_modules_do_not_import_worker_secret_material() -> None:
    import outcome.api.main as api_main
    import outcome.mcp.server as mcp_server

    assert "SecretMaterial" not in vars(api_main)
    assert "SecretResolver" not in vars(api_main)
    assert "SecretMaterial" not in vars(mcp_server)
    assert "SecretResolver" not in vars(mcp_server)
