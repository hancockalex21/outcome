.PHONY: install lint typecheck test security-test migrate dev mcp benchmark benchmark-report benchmark-update-golden

PYTHON ?= python3.12
VENV ?= .venv
BIN := $(VENV)/bin

install:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

lint:
	$(BIN)/python -m ruff check .

typecheck:
	$(BIN)/python -m mypy

test:
	$(BIN)/python -m pytest

security-test:
	$(BIN)/python -m pytest tests/test_security_hardening.py

migrate:
	$(BIN)/python -m alembic upgrade head

dev:
	$(BIN)/python -m uvicorn outcome.api.main:app --host 0.0.0.0 --port 8000 --reload

mcp:
	$(BIN)/outcome-mcp

benchmark:
	$(BIN)/python -m outcome.benchmarks.cli --output benchmarks/latest-report.json

benchmark-report: benchmark

benchmark-update-golden:
	$(BIN)/python -m outcome.benchmarks.cli --update-golden --output benchmarks/latest-report.json
