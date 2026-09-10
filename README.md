# Outcome

Outcome is an independent trust and authorization control plane for autonomous AI agents.

This repository is a production-oriented skeleton only. It includes application wiring,
local infrastructure, migrations, tests, and developer commands, but no Outcome product
logic yet.

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
make migrate
make dev
```

## Local Services

The default local service names are:

- Postgres: `postgres:5432`
- Redis: `redis:6379`

Copy `.env.example` to `.env` for local overrides. The example file intentionally
contains variable names only and no secret values.
