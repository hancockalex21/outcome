from __future__ import annotations

import json
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from outcome.onboarding import collect_beta_metrics


def main() -> None:
    database_url = os.environ.get("OUTCOME_BETA_REGISTRATION_DATABASE_URL", "")
    if not database_url:
        raise SystemExit("OUTCOME_BETA_REGISTRATION_DATABASE_URL is required")
    engine = create_engine(database_url)
    try:
        with Session(engine) as session:
            metrics = collect_beta_metrics(session)
        print(json.dumps(metrics.__dict__, sort_keys=True))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
