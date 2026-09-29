from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import DateTime, Integer, String, Uuid, inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.engine.reflection import Inspector

EXPECTED_REVISION = "20260929_0018"
CAPACITY_TABLE = "beta_registration_capacity"
REGISTRATIONS_TABLE = "beta_registrations"


@dataclass(frozen=True)
class InspectionCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class InspectionReport:
    checks: tuple[InspectionCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def to_safe_dict(self) -> dict[str, object]:
        return {
            "status": "PASS" if self.passed else "FAIL",
            "checks": [
                {
                    "name": check.name,
                    "status": "PASS" if check.passed else "FAIL",
                    "detail": check.detail,
                }
                for check in self.checks
            ],
        }


def inspect_beta_registration_schema(connection: Connection) -> InspectionReport:
    if connection.dialect.name != "postgresql":
        return InspectionReport(
            (InspectionCheck("database_dialect", False, "PostgreSQL is required"),)
        )
    checks: list[InspectionCheck] = []
    inspector = inspect(connection)
    tables = set(inspector.get_table_names(schema="public"))

    if "alembic_version" in tables:
        revision = (
            connection.execute(text("SELECT version_num FROM public.alembic_version"))
            .scalars()
            .all()
        )
    else:
        revision = []
    checks.append(
        InspectionCheck(
            "alembic_revision",
            revision == [EXPECTED_REVISION],
            f"expected {EXPECTED_REVISION}; rows={len(revision)}; "
            f"match={revision == [EXPECTED_REVISION]}",
        )
    )
    required_tables = {CAPACITY_TABLE, REGISTRATIONS_TABLE}
    missing = sorted(required_tables - tables)
    checks.append(
        InspectionCheck(
            "required_tables",
            not missing,
            "both required tables exist" if not missing else f"missing: {', '.join(missing)}",
        )
    )
    if missing:
        for name in (
            "columns",
            "primary_keys",
            "foreign_keys",
            "unique_constraints",
            "composite_index",
            "capacity_singleton",
            "capacity_consistency",
            "registration_integrity",
            "promotional_ledger_integrity",
            "registration_invariants",
        ):
            checks.append(InspectionCheck(name, False, "not checked because a table is missing"))
        return InspectionReport(tuple(checks))

    checks.append(_check_columns(inspector))
    checks.append(_check_primary_keys(inspector))
    checks.append(_check_foreign_keys(inspector, connection))
    checks.append(_check_unique_constraints(inspector, connection))
    checks.append(_check_index(inspector))
    checks.extend(_check_capacity(connection))
    checks.append(_count_check(connection, "registration_integrity", _REFERENTIAL_SQL))
    checks.append(_count_check(connection, "promotional_ledger_integrity", _LEDGER_SQL))
    checks.append(_count_check(connection, "registration_invariants", _REGISTRATION_SQL))
    return InspectionReport(tuple(checks))


def _check_columns(inspector: Inspector) -> InspectionCheck:
    expected = {
        CAPACITY_TABLE: {
            "id": ("integer", False, "nextval"),
            "registrations_used": ("integer", False, "none"),
            "created_at": ("timestamptz", False, "now"),
            "updated_at": ("timestamptz", False, "now"),
        },
        REGISTRATIONS_TABLE: {
            "id": ("uuid", False, "none"),
            "idempotency_key_hash": ("varchar:128", False, "none"),
            "request_fingerprint": ("varchar:128", False, "none"),
            "agent_id": ("uuid", False, "none"),
            "credential_id": ("uuid", False, "none"),
            "policy_id": ("uuid", False, "none"),
            "promotional_ledger_transaction_id": ("uuid", False, "none"),
            "promotional_credit_micro_usd": ("integer", False, "none"),
            "status": ("varchar:64", False, "none"),
            "account_id": ("uuid", False, "none"),
            "created_at": ("timestamptz", False, "now"),
            "updated_at": ("timestamptz", False, "now"),
        },
    }
    problems: list[str] = []
    for table, specifications in expected.items():
        columns = {
            column["name"]: column for column in inspector.get_columns(table, schema="public")
        }
        if set(columns) != set(specifications):
            problems.append(f"{table}: column names differ")
            continue
        for name, (kind, nullable, expected_default) in specifications.items():
            column = columns[name]
            if _type_kind(column["type"]) != kind:
                problems.append(f"{table}.{name}: type differs")
            if bool(column["nullable"]) != nullable:
                problems.append(f"{table}.{name}: nullability differs")
            default = str(column.get("default") or "").lower()
            if expected_default == "now" and "now()" not in default:
                problems.append(f"{table}.{name}: now() default missing")
            if expected_default == "nextval" and "nextval(" not in default:
                problems.append(f"{table}.{name}: sequence default missing")
            if expected_default == "none" and default:
                problems.append(f"{table}.{name}: unexpected default")
    return InspectionCheck(
        "columns",
        not problems,
        "columns match migration" if not problems else "; ".join(problems),
    )


def _type_kind(value: object) -> str:
    if isinstance(value, Uuid):
        return "uuid"
    if isinstance(value, Integer):
        return "integer"
    if isinstance(value, DateTime):
        return "timestamptz" if value.timezone else "timestamp"
    if isinstance(value, String):
        return f"varchar:{value.length}"
    return type(value).__name__.lower()


def _check_primary_keys(inspector: Inspector) -> InspectionCheck:
    actual = {
        table: tuple(inspector.get_pk_constraint(table, schema="public")["constrained_columns"])
        for table in (CAPACITY_TABLE, REGISTRATIONS_TABLE)
    }
    expected = {CAPACITY_TABLE: ("id",), REGISTRATIONS_TABLE: ("id",)}
    return InspectionCheck(
        "primary_keys",
        actual == expected,
        "primary keys match migration" if actual == expected else "primary key columns differ",
    )


def _check_foreign_keys(inspector: Inspector, connection: Connection) -> InspectionCheck:
    expected = {
        ("account_id",): ("accounts", ("id",), "CASCADE"),
        ("credential_id",): ("agent_credentials", ("id",), "RESTRICT"),
        ("policy_id",): ("policies", ("id",), "RESTRICT"),
        ("promotional_ledger_transaction_id",): (
            "credit_ledger_transactions",
            ("transaction_id",),
            "RESTRICT",
        ),
    }
    actual = {}
    unvalidated = False
    for foreign_key in inspector.get_foreign_keys(REGISTRATIONS_TABLE, schema="public"):
        actual[tuple(foreign_key["constrained_columns"])] = (
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
            str(foreign_key.get("options", {}).get("ondelete", "NO ACTION")).upper(),
        )
    validation_rows = connection.execute(
        text(
            "SELECT bool_and(convalidated) FROM pg_constraint "
            "WHERE conrelid = 'public.beta_registrations'::regclass AND contype = 'f'"
        )
    ).scalar_one()
    unvalidated = validation_rows is not True
    passed = actual == expected and not unvalidated
    return InspectionCheck(
        "foreign_keys",
        passed,
        "four validated foreign keys match migration"
        if passed
        else "foreign keys differ or are unvalidated",
    )


def _check_unique_constraints(inspector: Inspector, connection: Connection) -> InspectionCheck:
    expected = {
        "uq_beta_registrations_account": ("account_id",),
        "uq_beta_registrations_credential": ("credential_id",),
        "uq_beta_registrations_idempotency_hash": ("idempotency_key_hash",),
        "uq_beta_registrations_policy": ("policy_id",),
        "uq_beta_registrations_promotional_ledger": ("promotional_ledger_transaction_id",),
    }
    actual = {
        constraint["name"]: tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(REGISTRATIONS_TABLE, schema="public")
    }
    validation_rows = connection.execute(
        text(
            "SELECT bool_and(convalidated) FROM pg_constraint "
            "WHERE conrelid = 'public.beta_registrations'::regclass AND contype = 'u'"
        )
    ).scalar_one()
    passed = actual == expected and validation_rows is True
    return InspectionCheck(
        "unique_constraints",
        passed,
        "five validated unique constraints match migration"
        if passed
        else "unique constraints differ or are unvalidated",
    )


def _check_index(inspector: Inspector) -> InspectionCheck:
    matching = [
        index
        for index in inspector.get_indexes(REGISTRATIONS_TABLE, schema="public")
        if index["name"] == "ix_beta_registrations_account_created_at"
    ]
    passed = (
        len(matching) == 1
        and tuple(matching[0]["column_names"])
        == (
            "account_id",
            "created_at",
        )
        and not matching[0]["unique"]
    )
    return InspectionCheck(
        "composite_index",
        passed,
        "composite index matches migration" if passed else "composite index missing or different",
    )


def _check_capacity(connection: Connection) -> tuple[InspectionCheck, InspectionCheck]:
    rows = connection.execute(
        text("SELECT id, registrations_used FROM public.beta_registration_capacity ORDER BY id")
    ).all()
    registration_count = int(
        connection.execute(text("SELECT count(*) FROM public.beta_registrations")).scalar_one()
    )
    singleton = len(rows) == 1 and rows[0].id == 1 and rows[0].registrations_used >= 0
    consistent = singleton and rows[0].registrations_used == registration_count
    return (
        InspectionCheck(
            "capacity_singleton",
            singleton,
            "singleton id=1 is present and non-negative"
            if singleton
            else f"capacity rows={len(rows)} or singleton is invalid",
        ),
        InspectionCheck(
            "capacity_consistency",
            consistent,
            f"registrations={registration_count}; counts_match={consistent}",
        ),
    )


def _count_check(connection: Connection, name: str, statement: str) -> InspectionCheck:
    violations = int(connection.execute(text(statement)).scalar_one())
    return InspectionCheck(
        name,
        violations == 0,
        f"violations={violations}",
    )


_REFERENTIAL_SQL = """
SELECT count(*)
FROM public.beta_registrations br
LEFT JOIN public.accounts a ON a.id = br.account_id
LEFT JOIN public.agent_credentials ac ON ac.id = br.credential_id
LEFT JOIN public.policies p ON p.id = br.policy_id
LEFT JOIN public.credit_ledger_transactions clt
  ON clt.transaction_id = br.promotional_ledger_transaction_id
WHERE a.id IS NULL OR ac.id IS NULL OR p.id IS NULL OR clt.transaction_id IS NULL
   OR ac.account_id <> br.account_id OR ac.agent_id <> br.agent_id
   OR p.account_id <> br.account_id
   OR clt.account_id <> br.account_id
"""

_LEDGER_SQL = """
SELECT count(*) FROM (
  SELECT br.id
  FROM public.beta_registrations br
  JOIN public.credit_ledger_transactions clt
    ON clt.transaction_id = br.promotional_ledger_transaction_id
  LEFT JOIN public.credit_ledger_entries cle ON cle.transaction_id = clt.transaction_id
  GROUP BY br.id, br.account_id, br.promotional_credit_micro_usd,
           clt.transaction_type, clt.amount_micro_usd, clt.currency
  HAVING clt.transaction_type IS DISTINCT FROM 'promotional_credit'
      OR clt.amount_micro_usd IS DISTINCT FROM br.promotional_credit_micro_usd
      OR count(cle.id) <> 2
      OR bool_or(cle.account_id IS DISTINCT FROM br.account_id)
      OR clt.currency IS DISTINCT FROM 'USD'
      OR bool_or(cle.currency IS DISTINCT FROM 'USD')
      OR coalesce(sum(CASE cle.direction WHEN 'DEBIT' THEN cle.amount_micro_usd
                       WHEN 'CREDIT' THEN -cle.amount_micro_usd ELSE 0 END), 1) <> 0
      OR count(*) FILTER (
           WHERE cle.ledger_account = 'promotional_credit_expense'
             AND cle.direction = 'DEBIT'
             AND cle.amount_micro_usd = br.promotional_credit_micro_usd
         ) <> 1
      OR count(*) FILTER (
           WHERE cle.ledger_account = 'customer_prepaid_liability'
             AND cle.direction = 'CREDIT'
             AND cle.amount_micro_usd = br.promotional_credit_micro_usd
         ) <> 1
) violations
"""

_REGISTRATION_SQL = """
SELECT count(*)
FROM public.beta_registrations br
JOIN public.agent_credentials ac ON ac.id = br.credential_id
JOIN public.policies p ON p.id = br.policy_id
WHERE br.status IS DISTINCT FROM 'COMPLETED'
   OR length(br.idempotency_key_hash) <> 64
   OR length(br.request_fingerprint) <> 64
   OR br.promotional_credit_micro_usd <= 0
   OR br.promotional_credit_micro_usd > 10000000
   OR ac.scopes::jsonb IS DISTINCT FROM '["authorize:write"]'::jsonb
   OR ac.disabled_at IS NOT NULL OR ac.revoked_at IS NOT NULL
   OR p.name IS DISTINCT FROM 'Outcome controlled-beta harmless-action starter'
   OR p.version IS DISTINCT FROM 1
   OR p.status IS DISTINCT FROM 'PUBLISHED'
   OR p.body::jsonb ->> 'enabled' IS DISTINCT FROM 'true'
   OR p.body::jsonb ->> 'action_schema_version' IS DISTINCT FROM 'action.material.v1'
   OR jsonb_array_length(p.body::jsonb -> 'rules') IS DISTINCT FROM 1
   OR p.body::jsonb #>> '{rules,0,effect}' IS DISTINCT FROM 'ALLOW'
   OR p.body::jsonb #> '{rules,0,action_types}'
        IS DISTINCT FROM '["controlled_beta_test"]'::jsonb
   OR p.body::jsonb #> '{rules,0,capabilities}' IS DISTINCT FROM '["authorize"]'::jsonb
   OR p.body::jsonb #>> '{rules,0,required_assurance}' IS DISTINCT FROM 'STANDARD'
   OR p.body::jsonb #>> '{rules,0,max_amount_micro_usd}' IS DISTINCT FROM '0'
   OR p.body::jsonb #> '{rules,0,allowed_destinations}'
        IS DISTINCT FROM '["synthetic-resource"]'::jsonb
"""


__all__ = [
    "EXPECTED_REVISION",
    "InspectionCheck",
    "InspectionReport",
    "inspect_beta_registration_schema",
]
