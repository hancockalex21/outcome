# Outcome Controlled Beta Deployment

This is a production-shaped foundation for controlled external-agent testing. It is not a
hyperscale or high-availability deployment design.

## Deployment Model

Use portable Docker containers on a simple managed container platform such as Render, Railway,
or Fly.io. The repository intentionally keeps vendor-specific files out of the critical path:
the required primitives are containers, HTTPS ingress, managed Postgres, managed Redis, secret
environment variables, health checks, and logs.

Run one release migration job per deploy:

```bash
alembic upgrade head
```

Do not run migrations from every API/MCP/worker replica.

## Process Topology

Run three explicit process roles:

- API: `outcome-api`, exposes FastAPI health/readiness and future HTTP APIs.
- Remote MCP: `outcome-mcp-http`, exposes official MCP Streamable HTTP at `OUTCOME_MCP_HTTP_PATH`.
- Worker: `outcome-worker`, owns worker-only secret resolution and provider execution.

Local stdio MCP remains available with:

```bash
make mcp
```

Remote MCP is:

```bash
make mcp-http
```

## Secrets Matrix

API/MCP:

- Postgres URL.
- Redis URL.
- API credential verification data through the database.
- Receipt signing material only where authorization receipt issuance currently runs.
- Stripe webhook/payment secrets only when prepaid funding is enabled in that process.

Worker:

- Postgres/Redis access as required by worker tasks.
- Worker secret resolver credentials or external secret-manager references.
- Managed provider credential references/resolver access.
- No unnecessary Stripe secrets.

API/MCP must not receive BYOK plaintext provider credentials. Provider plaintext secrets may
exist only inside worker-side execution boundaries.

## Configuration Validation

Production mode rejects:

- wildcard CORS;
- development receipt signing key IDs;
- remote MCP without a receipt private key;
- remote MCP with local SQLite;
- worker using the development secret resolver backend;
- enabled Stripe funding without Stripe secret and webhook secret;
- reservation TTL shorter than the configured billable execution window plus safety margin.

Development mode keeps local defaults usable.

## Redis Assumptions

Redis stores temporary reservations only. Postgres remains authoritative money. Redis must be
configured with enough memory for reservations and should avoid eviction policies that remove
active reservation keys unpredictably. Redis restart/loss can make reservation state ambiguous;
Outcome fail-closes and requires reconciliation instead of assuming funds exist.

## Health Checks

- `/healthz`: process liveness only.
- `/readyz`: bounded readiness checks for config, Postgres, and Redis. Responses do not expose
  URLs, credentials, topology details, or stack traces.

## Remote MCP Authentication

Remote MCP clients send existing Outcome API credentials in the HTTP `Authorization` header:

```text
Authorization: Bearer oc_agent_...
```

The authenticated credential determines account and scopes. Tool arguments cannot establish
tenant identity.

## Request Limits And Timeouts

Configure:

- `OUTCOME_API_REQUEST_MAX_BYTES`
- `OUTCOME_MCP_REQUEST_MAX_BYTES`
- `OUTCOME_MCP_SESSION_IDLE_TIMEOUT_SECONDS`
- `OUTCOME_MCP_ALLOWED_HOSTS`
- `OUTCOME_RESERVATION_TTL_SECONDS`
- `OUTCOME_MAX_BILLABLE_EXECUTION_WINDOW_SECONDS`
- `OUTCOME_RESERVATION_TTL_SAFETY_MARGIN_SECONDS`

The reservation TTL must be at least the maximum billable execution window plus safety margin.

## Database Pool

Use conservative controlled-beta settings:

- `OUTCOME_DATABASE_POOL_SIZE`
- `OUTCOME_DATABASE_MAX_OVERFLOW`
- `OUTCOME_DATABASE_POOL_TIMEOUT_SECONDS`
- `OUTCOME_DATABASE_POOL_RECYCLE_SECONDS`

Avoid multiplying processes until the managed Postgres connection budget is known.

## Local Production-Shaped Topology

Run:

```bash
docker compose up --build
```

This starts Postgres, Redis, API, remote MCP, and worker with local development settings.

Run startup validation:

```bash
make production-smoke
```

## CI Database And Cache Topology

The primary CI job provisions PostgreSQL 16 and Redis 7 service containers. `make test` keeps
SQLite for isolated unit tests, runs the complete Alembic upgrade/downgrade chain against a
temporary PostgreSQL database, runs PostgreSQL concurrency tests, and exercises Redis-backed
reservation, billing, and MCP tests. `OUTCOME_POSTGRES_ADMIN_URL` is required for the migration
test; without it that integration test skips explicitly rather than pretending SQLite is the
production migration target.

A separate CI job runs `make acceptance-local`. That job launches the Compose production-shaped
PostgreSQL/Redis/MCP topology and executes the Prompt 32 client as an external subprocess.

## Safe Smoke Test

After deploy:

```bash
curl -fsS https://<api-host>/healthz
curl -fsS https://<api-host>/readyz
```

Then connect an MCP client to:

```text
https://<mcp-host>/mcp
```

with an `Authorization: Bearer oc_agent_...` header.

## Rollback

Roll back application images first. Database downgrades are not generally safe after production
traffic without explicit migration review. If a deployment fails after migrations, disable ingress
and inspect durable state before attempting downgrade.

## Emergency Controls

- Disable external traffic at ingress.
- Revoke API credentials in the database.
- Rotate receipt signing keys using key IDs; do not delete historical verification public keys
  needed for existing receipts.
- Rotate provider/BYOK secret-manager access in the worker process only.

## Remaining Beta Blockers

Before broader production launch, Outcome still needs external penetration testing, mature
disaster recovery, real provider SSRF protections for network transports, operational alerting,
refund/dispute economics, and production KMS/secret-manager integration.
