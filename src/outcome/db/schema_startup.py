from __future__ import annotations

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text

from outcome.core.config import Settings
from outcome.db import models  # noqa: F401  # register every mapped table before validation
from outcome.db.metadata import metadata

LOCAL_ENVIRONMENTS = frozenset({"local", "test", "development", "dev"})


class SchemaStartupError(RuntimeError):
    pass


def prepare_mcp_schema(engine: Engine, settings: Settings) -> None:
    """Bootstrap explicit local fixtures or validate deployed schema without mutating it."""
    environment = settings.env.strip().lower()
    local_bootstrap = environment in LOCAL_ENVIRONMENTS and (
        settings.mcp_local_schema_bootstrap_enabled
        or settings.mcp_database_url.startswith("sqlite:")
    )
    if local_bootstrap:
        metadata.create_all(engine)
        return
    validate_deployed_schema(engine, expected_revision=packaged_alembic_head())


def validate_deployed_schema(engine: Engine, *, expected_revision: str) -> None:
    inspector = inspect(engine)
    if not inspector.has_table("alembic_version"):
        raise SchemaStartupError(
            "database schema is not migration-managed: alembic_version is missing; "
            "run migrations before starting MCP"
        )
    with engine.connect() as connection:
        revisions = tuple(
            connection.execute(text("SELECT version_num FROM alembic_version")).scalars()
        )
    if revisions != (expected_revision,):
        rendered = ",".join(revisions) if revisions else "none"
        raise SchemaStartupError(
            "database migration revision mismatch: "
            f"expected {expected_revision}, found {rendered}; run migrations before starting MCP"
        )
    existing = set(inspector.get_table_names())
    missing = sorted(set(metadata.tables) - existing)
    if missing:
        raise SchemaStartupError(
            "database schema is incomplete for the current application revision; "
            f"missing tables: {', '.join(missing)}"
        )


def packaged_alembic_head() -> str:
    head = ScriptDirectory.from_config(Config("alembic.ini")).get_current_head()
    if head is None:
        raise SchemaStartupError("packaged Alembic migration head is unavailable")
    return head


__all__ = [
    "SchemaStartupError",
    "packaged_alembic_head",
    "prepare_mcp_schema",
    "validate_deployed_schema",
]
