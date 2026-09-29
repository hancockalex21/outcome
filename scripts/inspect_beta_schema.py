from __future__ import annotations

import json
import os

from sqlalchemy import create_engine

from outcome.operations import inspect_beta_registration_schema


def main() -> None:
    database_url = os.environ.get("OUTCOME_BETA_REGISTRATION_DATABASE_URL", "")
    if not database_url:
        raise SystemExit("OUTCOME_BETA_REGISTRATION_DATABASE_URL is required")
    engine = create_engine(database_url, pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                connection.exec_driver_sql("SET TRANSACTION READ ONLY")
                report = inspect_beta_registration_schema(connection)
            finally:
                transaction.rollback()
        print(json.dumps(report.to_safe_dict(), indent=2, sort_keys=True))
        raise SystemExit(0 if report.passed else 1)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
