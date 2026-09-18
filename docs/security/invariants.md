# Outcome Security Invariants v1

These invariants are non-negotiable unless explicitly replaced by a reviewed security
design.

- Tenant identity derives from authentication, not request payload fields.
- Account-scoped object references must be checked against the authenticated account.
- Agent API keys are stored only as secure hashes; plaintext is returned only once at
  development/admin creation.
- Plaintext BYOK secrets exist only inside worker-side provider execution.
- Managed provider credentials follow the same no-plaintext-in-API/audit/persistence
  rule.
- Provider responses and external evidence are hostile until normalized into inert
  evidence.
- Source authority, extraction quality, and evidence independence remain separate.
- Evidence Score is an integer evidence-strength score, not a probability.
- Only `PolicyDecision.ALLOW` can receive an executable signed receipt.
- Receipts bind exact material action, account, policy version, schema version, and
  expiry.
- Consumed receipts cannot execute twice under default one-time semantics.
- Postgres double-entry ledger is the authoritative money source of truth.
- Redis reservations are temporary spend controls and cannot create money.
- Financial effects are DB-idempotent and tenant scoped.
- Invalid Stripe webhooks cannot create inbox rows or mutate financial state.
- `SYSTEM_FAILURE` is not customer billable under current V1 billing semantics.
- MCP cannot bypass application services or expose internal mutation/provider/secret
  tools.
- Provider destinations are configured by Outcome/provider setup, not caller selected.
- Provider execution must reject localhost/private/link-local/metadata destinations.
- Fail-closed behavior takes priority over convenience when state is ambiguous.
