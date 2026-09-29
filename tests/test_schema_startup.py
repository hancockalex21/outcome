from __future__ import annotations

import pytest
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from outcome.core.config import Settings
from outcome.db import models  # noqa: F401
from outcome.db.metadata import metadata
from outcome.db.schema_startup import (
    SchemaStartupError,
    prepare_mcp_schema,
    validate_deployed_schema,
)
from outcome.mcp import main as mcp_main


def sqlite_engine() -> Engine:
    return create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def test_production_startup_never_creates_missing_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sqlite_engine()
    create_all_called = False

    def forbidden_create_all(*args: object, **kwargs: object) -> None:
        nonlocal create_all_called
        create_all_called = True
        raise AssertionError("production attempted schema creation")

    monkeypatch.setattr(metadata, "create_all", forbidden_create_all)
    settings = Settings(
        env="production",
        mcp_database_url="postgresql+psycopg://production.invalid/outcome",
    )

    with pytest.raises(SchemaStartupError, match="alembic_version is missing"):
        prepare_mcp_schema(engine, settings)

    assert create_all_called is False
    assert inspect(engine).get_table_names() == []


def test_production_mcp_session_factory_fails_without_schema_and_does_not_create_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = sqlite_engine()
    settings = Settings(
        env="production",
        mcp_database_url="postgresql+psycopg://production.invalid/outcome",
    )
    monkeypatch.setattr(mcp_main, "get_settings", lambda: settings)
    monkeypatch.setattr(mcp_main, "create_engine", lambda _url: engine)

    with pytest.raises(SchemaStartupError, match="alembic_version is missing"):
        mcp_main.build_session_factory()

    assert inspect(engine).get_table_names() == []


def test_explicit_local_sqlite_bootstrap_remains_available() -> None:
    engine = sqlite_engine()
    settings = Settings(env="local", mcp_database_url="sqlite://")

    prepare_mcp_schema(engine, settings)

    assert set(metadata.tables) <= set(inspect(engine).get_table_names())


def test_deployed_schema_validation_is_read_only_and_requires_exact_revision() -> None:
    engine = sqlite_engine()
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        connection.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
            {"revision": "expected-head"},
        )

    validate_deployed_schema(engine, expected_revision="expected-head")
    with pytest.raises(SchemaStartupError, match="revision mismatch"):
        validate_deployed_schema(engine, expected_revision="different-head")
