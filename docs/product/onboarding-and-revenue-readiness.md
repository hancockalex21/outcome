# Onboarding and revenue readiness

## Current-path audit

Authentication derives account and agent identity from a hashed, scoped `oc_agent_*` bearer
credential. The client cannot choose a tenant. Policies are immutable published versions and
policy evaluation is tenant-scoped, deterministic, deny-by-default, and audited. Verification
results contain orchestrator-produced status, score, evidence references, assurance, and
provenance and are tenant-checked before authorization. Authorization binds the policy,
verification, exact canonical material action, expiry, and tenant into an auditable result and
an ALLOW-only Ed25519 receipt. Receipt consumption revalidates tenant, signature, expiry, and
exact action, then records one-time use. Prepaid authorization billing reserves credit and
settles through the double-entry Postgres ledger with idempotent request and settlement keys.

### Why the two identifiers existed

| Requirement | Original reason | Classification | Decision |
|---|---|---|---|
| Policy identity/version | Pins evaluation and receipt provenance to one immutable tenant policy; prevents client-selected drift | Essential security boundary; policy is a legitimate product concept, raw UUID transfer is an implementation detail | Retain explicit selection; add tenant-local, unique, fail-closed resolution |
| Verification-result identity | References orchestrator-produced evidence/status and prevents a client from asserting `VERIFIED` | Essential security boundary; verification is a legitimate product concept, pre-provisioned UUID transfer is a controlled-beta artifact | Retain explicit compatibility; accept claim/subject and invoke the existing orchestrator internally |
| Bearer credential | Authenticates tenant/agent and scopes tools | Essential security boundary | Retain; improve client-secret configuration guidance |
| Policy provisioning | Hosted policy administration is operator-only | Temporary controlled-beta artifact | Retain for now; do not expose broad administration through agent MCP |
| Pre-provisioned verified result | Compensates for no hosted MCP provider plan | Temporary controlled-beta artifact | Retain until one bounded approved provider path is operational |

Automatic policy resolution considers only currently effective published policies belonging to
the authenticated account and matching action schema plus action type/capability. It does not
choose based on which policy would allow, ignore constraints, or cross tenant boundaries.
Zero or multiple candidates fail closed. The selected policy still undergoes the unchanged
full evaluation. Explicit policy selection remains available.

Claim-based authorization creates an internal verification envelope and calls the existing
`VerificationOrchestrator`; it does not duplicate scoring or accept status/score fields. The
current hosted application supplies no provider plan, so this path safely produces a provider
failure until an approved provider is configured. Existing results remain subject to tenant,
status, assurance, score, and policy checks.

## Prioritized adoption and revenue gaps

### A. First external free user

The controlled-beta registration API now creates one tenant, authorization-only credential,
starter policy, and bounded promotional balance without database manipulation. Remaining work:

1. Configure and securely distribute invite tokens for the first cohort.
2. Publish the quickstart at a stable URL and exercise registration plus authorization in production.
3. Define the operator procedure for lost-response credential revocation and replacement.
4. Configure a verification provider only for workflows beyond the verification-free starter action.

Automatic policy resolution removes identifier transfer when the account has exactly one
applicable policy. It intentionally does not remove operator policy provisioning.

### B. First paid user

1. Expose a narrow authenticated account-funding flow backed by the existing `FundingService`
   and real payment gateway/webhook adapter; no dashboard is required.
2. Establish price disclosure, terms/refund/support policy, and a customer-visible safe balance
   or funding confirmation mechanism.
3. Issue the paid agent a scoped credential and attribute each authorization charge to account,
   credential/agent, authorization request, pricing version, reservation, and settlement.
   The current ledger and authorization billing records already preserve these identifiers and
   exactly-once semantics.
4. Complete one production payment-to-ledger reconciliation drill, then one low-value paid
   authorization without operator-minted credit.

The prepaid-credit architecture is sufficient for measuring legitimate agent-triggered usage
and revenue: Postgres double-entry entries are authoritative, Redis is only a reservation
layer, prices use integer micro-USD, and authorization idempotency prevents duplicate charges.
Registration and promotion are not payment or revenue. The blocker is a customer-facing paid
funding boundary and production reconciliation, not a new monetization model. `beta-metrics`
separately reports promotional issuance, customer-paid funding, and authorization usage; usage
must not be presented as customer-paid revenue when it was funded by promotion.

### C. Can wait until broader scale

- Self-service UI/dashboard, seats, enterprise administration, marketplaces, x402/MPP, and
  arbitrary plugins.
- Multiple policy routing conventions beyond unique deterministic resolution.
- Broad provider catalog, postpaid invoicing, refunds automation, and regional optimization.
- Automated key lifecycle, richer usage exports, and large-scale reconciliation operations.

These are not required for the first legitimate paid agent-triggered authorization before
December 31, 2026.
