from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, check=True, env=env)


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    artifacts = root / "artifacts"
    artifacts.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="outcome-acceptance-") as directory:
        fixture = Path(directory) / "fixture.json"
        run(["docker", "compose", "up", "-d", "postgres", "redis"])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["docker", "compose", "exec", "-T", "postgres", "pg_isready", "-U", "outcome"],
                capture_output=True,
            )
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("local Postgres did not become ready")
        run(
            [
                str(root / ".venv/bin/python"),
                "scripts/acceptance_operator.py",
                "--database-url",
                "postgresql+psycopg://outcome@127.0.0.1:5432/outcome",
                "--environment",
                "local",
                "--output",
                str(fixture),
            ]
        )
        values = json.loads(fixture.read_text(encoding="utf-8"))
        run(["docker", "compose", "up", "-d", "--build", "mcp"])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                response = httpx.post(
                    "http://127.0.0.1:8001/mcp",
                    headers={"Accept": "application/json, text/event-stream"},
                    timeout=2,
                )
                if response.status_code < 500:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
        else:
            raise RuntimeError("local MCP did not become ready")
        env = os.environ.copy()
        env.update(
            {
                "OUTCOME_MCP_URL": "http://127.0.0.1:8001/mcp",
                "OUTCOME_API_KEY": values["api_key"],
                "OUTCOME_ACCEPTANCE_POLICY_ID": values["policy_id"],
                "OUTCOME_ACCEPTANCE_VERIFICATION_RESULT_ID": values["verification_result_id"],
                "OUTCOME_ACCEPTANCE_ENV": "local-production-shaped",
                "OUTCOME_ACCEPTANCE_REPORT": str(artifacts / "acceptance-report.json"),
                "OUTCOME_RUN_ACCEPTANCE_SUBPROCESS": "1",
            }
        )
        completed = subprocess.run(
            [
                str(root / ".venv/bin/python"),
                "-m",
                "pytest",
                "tests/test_acceptance_subprocess.py",
                "-q",
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        combined = completed.stdout + completed.stderr
        if values["api_key"] in combined:
            raise RuntimeError("SECRET_SENTINEL_LEAK in acceptance client output")
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        if completed.returncode:
            raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
