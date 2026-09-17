.PHONY: install lint typecheck test migrate dev mcp

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

migrate:
	$(BIN)/python -m alembic upgrade head

dev:
	$(BIN)/python -m uvicorn outcome.api.main:app --host 0.0.0.0 --port 8000 --reload

mcp:
	$(BIN)/outcome-mcp
