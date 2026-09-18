# Runtime Dependency Security Review v1

This file documents the direct runtime dependencies currently declared in
`pyproject.toml`. It is not a vulnerability attestation.

| Package | Version Range | Purpose | Security-Sensitive Role |
| --- | --- | --- | --- |
| `alembic` | `>=1.13` | Database migrations | Schema integrity |
| `asyncpg` | `>=0.29` | Async Postgres driver | Database transport |
| `cryptography` | `>=43.0` | Ed25519 receipt signing | Cryptographic primitive provider |
| `fastapi` | `>=0.115` | HTTP API framework | Request validation/boundary |
| `httpx` | `>=0.27` | HTTP client support | Future outbound/client testing |
| `mcp` | `>=2.0,<3.0` | MCP stdio server | Agent integration boundary |
| `opentelemetry-*` | `>=1.25` / `>=0.46b0` | Telemetry | Must avoid secret/high-cardinality data |
| `pydantic` | `>=2.8` | Schema validation | Input validation |
| `pydantic-settings` | `>=2.4` | Config loading | Secret/config boundary |
| `redis` | `>=5.0` | Reservation layer | Fail-closed spend controls |
| `sqlalchemy[asyncio]` | `>=2.0` | ORM/database access | Persistence and SQL parameterization |
| `structlog` | `>=24.2` | Structured logging | Must not log secrets |
| `uvicorn[standard]` | `>=0.30` | ASGI server | HTTP serving |

No heavyweight scanner was added in Prompt 30. The repository now provides
`make security-test` for deterministic adversarial regression tests. A future CI hardening
pass should add a pinned, low-noise dependency vulnerability scanner such as `pip-audit`
after the team decides how dependency advisory failures are triaged.
