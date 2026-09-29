.PHONY: install lint typecheck test security-test security-check migrate dev mcp mcp-http benchmark benchmark-report benchmark-update-golden production-smoke acceptance-local beta-metrics inspect-beta-schema

PYTHON ?= python3.12
VENV ?= .venv
BIN := $(VENV)/bin
PIP_CONSTRAINT ?= requirements.lock

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -c $(PIP_CONSTRAINT) -e ".[dev]"

lint:
	$(BIN)/python -m ruff check .

typecheck:
	$(BIN)/python -m mypy

test:
	$(BIN)/python -m pytest

security-test:
	$(BIN)/python -m pytest tests/test_security_hardening.py

security-check:
	$(BIN)/python -m pip_audit -r requirements.lock --progress-spinner off

migrate:
	$(BIN)/python -m alembic upgrade head

dev:
	$(BIN)/python -m uvicorn outcome.api.main:app --host 0.0.0.0 --port 8000 --reload

mcp:
	$(BIN)/outcome-mcp

mcp-http:
	$(BIN)/outcome-mcp-http

benchmark:
	$(BIN)/python -m outcome.benchmarks.cli --output benchmarks/latest-report.json

benchmark-report: benchmark

benchmark-update-golden:
	$(BIN)/python -m outcome.benchmarks.cli --update-golden --output benchmarks/latest-report.json

production-smoke:
	$(BIN)/python scripts/production_smoke.py

acceptance-local:
	$(BIN)/python scripts/acceptance_local.py

beta-metrics:
	$(BIN)/python scripts/beta_metrics.py

inspect-beta-schema:
	$(BIN)/python scripts/inspect_beta_schema.py
