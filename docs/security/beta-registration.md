# Controlled-beta registration security and recovery

## Architecture

`POST /v1/beta/register` is disabled by default. Before database work, the API applies a
Redis-backed per-client rate limit and constant-time comparison of `X-Outcome-Beta-Token` against
the server-configured bootstrap secret. The token is never stored in application tables and never
becomes an agent credential.

One Postgres transaction locks the capacity row and creates the tenant, agent identity, salted
credential hash, immutable starter policy, promotional ledger posting, registration record, and
safe audit events. The record stores only a hash of the idempotency key and request fingerprint.
Missing or ambiguous capacity/abuse state fails closed.

## Threat model and invite limitations

- Brute force: long managed secret, constant-time digest comparison, bounded headers/body, and
  rate limiting before authentication.
- Credit farming: invite possession, global registration limit, unique idempotency hashes, and a
  hard 10,000,000 micro-USD promotional maximum.
- Replay: exact completed retries create nothing; changed input conflicts.
- Leakage: plaintext agent keys exist only in the successful response and call stack. Audit payload
  allowlisting excludes credentials and bootstrap tokens.
- Cross tenant: random tenant per registration; policy, credential, ledger, and MCP remain scoped.
- Partial/concurrent failure: one database transaction, row lock, post-lock idempotency recheck,
  uniqueness constraints, and rollback.
- Accidental exposure: disabled endpoint returns 404; production startup validates configuration.

Invite tokens are cohort-level bootstrap authorization, not identity proof. A leaked invite works
until rotation or registration/rate limits are reached. V1 deliberately avoids CAPTCHA,
fingerprinting, OAuth, and consumer identity infrastructure. Keep cohorts and promotional amounts
small, monitor use, and rotate promptly.

## Credential and recovery semantics

The initial credential has only `authorize:write`, uses `oc_agent_*`, and is revocable through the
existing credential service. It is returned exactly once. If commit succeeds but the response is
lost, retry returns HTTP 409 `credential recovery required` without creating or revealing value.
The operator must revoke the inaccessible credential and use a future narrow rotation procedure;
V1 never persists reversible plaintext.

## Policy and accounting

The starter policy allows only `controlled_beta_test`, capability `authorize`, STANDARD assurance,
zero amount, and destination `synthetic-resource`. Everything else fails closed.

Promotion uses transaction type `promotional_credit`, debiting `promotional_credit_expense` and
crediting prepaid liability. Customer payment remains `account_funding`; service adjustment is
`service_credit`; authorization consumption is `reservation_settlement`. Promotion is never paid
revenue. V1 has no credit-lot attribution, so authorization usage is reported separately from
customer funding and must not be called paid revenue merely because it was consumed.

## Audit, metrics, and first authorization

Safe events and the registration row link registration, tenant, credential ID, policy, and funding
without secrets. `make beta-metrics` (with its database URL injected by the secret manager)
reports registrations, accounts with authorization activity, promotion, authorization usage,
customer funding, and service credit. Customer funding is counted only from succeeded payment
records linked to ledger transactions, never from an operator's bare balance-credit operation.

The path is: invite → register → store agent key → configure returned MCP endpoint → call
`outcome_capabilities` → submit the quickstart's zero-value starter action.

Before real payment, Outcome still needs a narrow paid funding boundary, production payment
gateway/webhook configuration, price/terms disclosure, and a payment-to-ledger reconciliation drill.
