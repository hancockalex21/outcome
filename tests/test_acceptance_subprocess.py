from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(
    not os.getenv("OUTCOME_RUN_ACCEPTANCE_SUBPROCESS"),
    reason="requires an explicitly provisioned remote MCP acceptance target",
)
def test_external_acceptance_client_runs_as_black_box_subprocess() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [str(root / ".venv/bin/python"), "-m", "tools.acceptance.outcome_acceptance"],
        cwd=root,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report_path = Path(os.environ["OUTCOME_ACCEPTANCE_REPORT"])
    report_text = report_path.read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["overall_status"] == "PASS"
    assert os.environ["OUTCOME_API_KEY"] not in completed.stdout
    assert os.environ["OUTCOME_API_KEY"] not in completed.stderr
    assert os.environ["OUTCOME_API_KEY"] not in report_text
