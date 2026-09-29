# Outcome Controlled Beta Deployment

This is a production-shaped foundation for controlled external-agent testing. It is not a
hyperscale or high-availability deployment design.

## Deployment Model

Use portable Docker containers on a simple managed container platform such as Render, Railway,
or Fly.io. The repository intentionally keeps vendor-specific files out of the critical path:
the required primitives are containers, HTTPS ingress, managed Postgres, managed Redis, secret
environment variables, health checks, and logs.

Run one release migration job per deploy, and require it to complete successfully before starting
or replacing any API, MCP, or worker process:

```bash
alembic upgrade head
```

Do not run migrations from every API/MCP/worker replica. Alembic is the exclusive owner of
production schema changes. Production MCP startup performs a read-only check that the database is
at the packaged Alembic head and that all mapped tables exist. It exits with a migration-first
error when either condition is false; it never creates or repairs schema.

`OUTCOME_MCP_LOCAL_SCHEMA_BOOTSTRAP_ENABLED` is only for explicit local/test fixture workflows.
Production configuration rejects it. The Compose development MCP enables it because that local
workflow intentionally creates disposable fixture schema.

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
- enabled beta registration without a long bootstrap token, synchronous Postgres URL, bounded
  promotional amount, or production HTTPS MCP endpoint.

## Controlled-beta registration

Registration is disabled by default. Enable it only on the API process with:

- `OUTCOME_BETA_REGISTRATION_ENABLED=true`
- `OUTCOME_BETA_REGISTRATION_DATABASE_URL=postgresql+psycopg://...`
- `OUTCOME_BETA_REGISTRATION_BOOTSTRAP_TOKEN=<managed secret, at least 32 characters>`
- `OUTCOME_BETA_REGISTRATION_LIMIT=<bounded integer>`
- `OUTCOME_BETA_PROMOTIONAL_CREDIT_MICRO_USD=<integer, maximum 10000000>`
- `OUTCOME_BETA_REGISTRATION_RATE_LIMIT` and
  `OUTCOME_BETA_REGISTRATION_RATE_WINDOW_SECONDS`
- `OUTCOME_PUBLIC_MCP_ENDPOINT=https://.../mcp`
- `OUTCOME_PUBLIC_QUICKSTART_URL=https://...` (optional)

API replicas share authoritative capacity/idempotency state in Postgres and rate-limit state in
Redis. Registration fails closed when either is unavailable. Store and rotate the invite token in
the platform secret manager.

Safe aggregate reporting requires a read-only-capable database connection:

Run `make beta-metrics` in an operator process where the platform secret manager injects
`OUTCOME_BETA_REGISTRATION_DATABASE_URL`; do not put database credentials in shell history.

Before reconciling a deployment involving migration `20260929_0018`, run the read-only schema
inspection helper from an operator process where the same variable is injected by the platform
secret manager:

```bash
make inspect-beta-schema
```

The helper starts a read-only PostgreSQL transaction and emits a concise JSON PASS/FAIL report for
the Alembic revision, both beta tables, their migration-defined columns, defaults, keys,
constraints and index, plus capacity, tenant/reference, promotional-ledger, and registration
invariants. It does not print the database URL, mutate data, repair schema, or stamp Alembic. A
PASS is evidence for an operator-reviewed reconciliation decision; it does not itself perform one.

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
