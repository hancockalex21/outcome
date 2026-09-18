# Outcome Threat Model v1

This document describes the current security model for Outcome. It is a working
engineering threat model, not a penetration-test report, compliance claim, or formal
verification artifact.

## Assets

- Tenant data and tenant-scoped object references.
- Agent API credentials and credential metadata.
- Customer BYOK provider credentials.
- Outcome-managed provider credential references.
- Receipt signing keys and public verification keys.
- Signed authorization receipts and receipt-consumption records.
- Policy state, policy versions, and policy hashes.
- Normalized evidence, lineage, provenance, and audit events.
- Prepaid balances, double-entry ledger transactions, reservations, settlements, and
  billing records.
- Stripe/payment identifiers, funding records, and webhook inbox state.
- MCP tool inputs/results and discovery metadata.

## Trust Boundaries

- Agent/client to API/MCP.
- API/MCP adapter to application services.
- Application services to Postgres.
- Reservation services to Redis.
- API/control plane to worker/provider execution boundary.
- Worker/provider executor to secret resolver.
- Worker/provider executor to provider transport.
- Provider response to hostile evidence normalization.
- Stripe webhook payload/signature to payment service.
- Authorization orchestration to receipt signer.
- Signed receipt to execution gateway/validator.

## Attacker Classes

- Unauthenticated external caller.
- Malicious authenticated tenant.
- Compromised tenant agent/API key.
- Malicious or compromised upstream provider.
- Hostile evidence source.
- Replay attacker with valid historical artifacts.
- Concurrency/race attacker.
- Operator or configuration error.

## STRIDE Review

### Spoofing

Attack: caller supplies another tenant's `account_id`, `receipt_id`,
`verification_request_id`, provider ID, or billing reference.

Affected assets: tenant data, receipts, billing, evidence, secrets.

Existing controls: account context is derived from authenticated credentials; service
lookups are account scoped; receipt/action hashes bind account ID; secret resolution
requires account/provider/ref match.

Mitigation/test: cross-tenant tests cover API keys, evidence, receipts, billing,
reservations, provider secrets, MCP requests, and receipt consumption. Prompt 30 adds
security regression tests for object-reference and destination confusion.

Residual risk: broad end-to-end multi-tenant penetration testing is still required.

### Tampering

Attack: mutate material action, policy version, action schema version, expiration,
receipt payload, evidence lineage, or payment/webhook amount.

Affected assets: authorization decisions, receipts, ledger integrity, evidence score.

Existing controls: canonical action binding; Ed25519 receipt signatures; immutable
service-layer receipts/audit/evidence/lineage; ledger idempotency and DB uniqueness;
Stripe webhook signature verifier boundary.

Mitigation/test: canonicalization vectors, receipt tamper tests, one-time consumption
tests, funding concurrency tests, and Prompt 30 security tests for canonicalization
ambiguity and receipt tampering.

Residual risk: audit-chain cryptographic sealing is not implemented.

### Repudiation

Attack: deny that a request, decision, funding event, provider attempt, or consumption
occurred.

Affected assets: audit timeline, financial provenance, authorization provenance.

Existing controls: append-only service APIs for audit and ledger; durable records for
funding, billing, attempts, receipts, and consumption.

Mitigation/test: audit allowlist tests and lifecycle reconstruction tests.

Residual risk: logs/audit rows are not yet externally notarized or cryptographically
chained.

### Information Disclosure

Attack: leak API keys, Authorization headers, BYOK secrets, managed credentials,
signing private keys, webhook secrets/signatures, raw provider bodies, or stack traces.

Affected assets: credentials, private customer data, provider contracts, payment
secrets.

Existing controls: hash-only API key persistence; `SecretMaterial` redacted
representation; worker-only secret resolution; audit allowlist; raw evidence
normalization boundary; public receipt excludes private keys; MCP error sanitization.

Mitigation/test: secret sentinel tests, audit redaction tests, MCP sanitized error
tests, provider execution exception tests.

Residual risk: process memory inspection and host compromise are out of scope for this
stage; production secret manager/KMS integration remains future work.

### Denial Of Service

Attack: oversized evidence, huge/deep material actions, many providers, long
idempotency keys, Redis/DB/provider outages, cancellation races.

Affected assets: service availability and reservation safety.

Existing controls: evidence size/depth limits; provider collection concurrency and
deadline limits; reservation fail-closed behavior; canonicalization rejects unsafe
numbers and unsupported types.

Mitigation/test: bounded evidence tests, provider timeout/deadline tests, reservation
outage tests, Prompt 30 resource-boundary tests.

Residual risk: infrastructure-level rate limiting and WAF-style controls are not in
this repository.

### Elevation Of Privilege

Attack: use weaker scopes, provider rights confusion, BYOK/MANAGED mode confusion,
policy bypass, non-ALLOW receipt issuance, MCP internal tool invocation.

Affected assets: authorization decisions, provider credentials, ledger, receipts.

Existing controls: scoped API keys; provider rights service; execution-mode checks;
ALLOW-only receipt service; MCP exposes only verify/authorize/capabilities and
delegates to application services.

Mitigation/test: scope tests, provider rights tests, mode-confusion tests, receipt
issuance tests, MCP dangerous-tool absence tests.

Residual risk: production RBAC/admin workflows are not implemented yet and will need a
separate threat model update.

## Deferred Security Work

- Production KMS/HSM integration and signing-key rotation operations.
- External audit-chain sealing/notarization.
- Infrastructure rate limiting and abuse prevention.
- Production vulnerability scanning in CI.
- Independent penetration testing and cryptographic review.
- Refund/dispute/chargeback financial controls before broad card launch.
