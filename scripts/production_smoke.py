from __future__ import annotations

import base64
import os
from collections.abc import Iterator
from contextlib import contextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from outcome.api.main import _bounded_request_id
from outcome.core.config import Settings, validate_startup_config


def main() -> None:
    signing_key = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_b64 = base64.urlsafe_b64encode(signing_key).decode("ascii")
    settings = Settings(
        env="production",
        database_url="postgresql+asyncpg://outcome@postgres:5432/outcome",
        mcp_database_url="postgresql+psycopg://outcome@postgres:5432/outcome",
        redis_url="redis://redis:6379/0",
        mcp_receipt_signing_key_id="outcome-controlled-beta-key-1",
        mcp_receipt_private_key_b64=private_key_b64,
        worker_secret_resolver_backend="external-reference",
        reservation_ttl_seconds=900,
        max_billable_execution_window_seconds=600,
        reservation_ttl_safety_margin_seconds=120,
    )
    for role in ("api", "mcp", "worker"):
        validate_startup_config(settings, process_role=role)  # type: ignore[arg-type]
    assert _bounded_request_id("safe-request-1") == "safe-request-1"
    assert _bounded_request_id("unsafe header\nvalue") != "unsafe header\nvalue"
    with temporary_environment({"OUTCOME_ENV": "local"}):
        pass
    print("production smoke validation ok")


@contextmanager
def temporary_environment(values: dict[str, str]) -> Iterator[None]:
    original = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in original.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


if __name__ == "__main__":
    main()
