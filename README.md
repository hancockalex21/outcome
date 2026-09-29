# Outcome

Outcome is an independent trust and authorization control plane for autonomous AI agents.

This repository contains Outcome's policy, verification, authorization, billing, signed
receipt, and execution-boundary validation services.

New hosted-MCP users can start without this repository: see the
[external developer quickstart](docs/getting-started/external-mcp-quickstart.md).

## Quick Start

Requirements:

- Python 3.12
- Docker and Docker Compose

Install dependencies:

```sh
make install
```

This creates `.venv/` and installs the project with development dependencies.

Start Postgres and Redis:

```sh
docker compose up -d postgres redis
```

Run database migrations:

```sh
make migrate
```

Start the API:

```sh
make dev
```

Start the local MCP server over stdio:

```sh
make mcp
```

The MCP server exposes `outcome_verify`, `outcome_authorize`, and
`outcome_capabilities`. Tool calls authenticate with existing Outcome agent API keys
using `Authorization: Bearer oc_agent_*` in each tool request envelope. The local
stdio server is an adapter over the same Outcome application services; it does not
expose provider execution, secret resolution, ledger mutation, receipt signing, or
arbitrary HTTP/file/code tools.

Check health:

```sh
curl http://127.0.0.1:8000/healthz
```

Expected response:

```json
{"status":"ok"}
```

## Commands

```sh
make install
make lint
make typecheck
make test
make security-test
make migrate
make dev
make mcp
make benchmark
```

## Local Services

The default local service names are:

- Postgres: `postgres:5432`
- Redis: `redis:6379`

Copy `.env.example` to `.env` for local overrides. The example file intentionally
contains variable names only and no secret values.
