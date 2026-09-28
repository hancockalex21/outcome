# Controlled-beta black-box acceptance

## Purpose

This gate proves that an external process can discover a deployed Outcome MCP service, authenticate with a normal `oc_agent_*` key, authorize one harmless material action through normal verification, policy, billing, and receipt paths, and consume the action-bound receipt through the public execution-validation boundary.

A passing report means only: **Outcome completed its controlled black-box acceptance workflow.** It does not prove product-market fit, independent adoption, production readiness, universal security, real-world verification accuracy, enterprise readiness, or autonomous revenue.

## What it proves—and does not

The client imports only the MCP SDK, HTTP client, and Python standard library. It discovers tools before use, rejects incompatible v1 contracts, tests missing and invalid authentication, handles all four PolicyDecision values, requires ALLOW for the canonical fixture, checks billing settlement metadata, checks the public receipt structure, verifies exact-action consumption at the server cryptographic boundary, rejects changed actions, proves one-time consumption, and checks authorization idempotency/conflicts.

It does not execute an external action, integrate a provider, validate private evidence, negotiate payment, call Stripe, administer policies publicly, mint public money, or configure a third-party agent.

## Local prerequisites

- Python 3.12 and `make install`
- Docker with Compose
- ports 5432, 6379, and 8001 available

The local topology uses Postgres and Redis. The MCP process uses a deterministic local-only Ed25519 key and is not production secret material.

## Fixture provisioning

`scripts/acceptance_operator.py` is an operator-only command, separate from the black-box client. It creates a dedicated account, a narrow published policy, one deterministic VERIFIED result, a normal scoped API key, and exactly 1,000,000 micro-USD of prepaid test funding through `LedgerService.fund_account`. Funding uses double-entry entries and an idempotency key prefixed `TEST_ACCEPTANCE`; it never mutates a balance directly and never calls Stripe. The command fails closed if its fixed controlled-beta account and agent already have a credential, so it cannot be used to silently issue a second key.

The policy allows only `controlled_beta_test` / `authorize`, destination `synthetic-resource`, zero action amount, STANDARD assurance, VERIFIED status, and score ≥9000. There is no always-allow branch.

No fixture provider is added. The operator-provisioned result avoids introducing a provider backdoor; the agent receives only its public result ID. A future controlled beta must provision an equivalently bounded result using an approved existing path.

## Local run

```bash
make acceptance-local
```

The command starts Postgres/Redis, provisions fixtures, builds and starts MCP, launches the acceptance client as a separate process over HTTP/MCP, and writes `artifacts/acceptance-report.json`. Failures propagate as a non-zero exit. The credential fixture file is mode 0600 in a temporary directory and is deleted automatically.

## Remote deployment prerequisites

The operator must deploy the Prompt 31 topology, inject a non-development receipt signing key, create a dedicated low-value account and least-privilege `authorize:write` key, publish the narrow policy, provision a VERIFIED acceptance result through an approved controlled path, and add a small prepaid balance through existing operator funding semantics. Remote mode does none of these operations.

## Credential, policy, and prepaid setup

Use existing operator procedures to issue an `oc_agent_*` key. Do not transmit account identity in the request; Outcome derives it from the credential. Publish the policy described above as version 1. Use a `TEST_ACCEPTANCE`-identified funding operation through the ledger service. Never expose policy admin or funding as public MCP tools.

## Run the external client

```bash
OUTCOME_MCP_URL=https://beta.example/mcp \
OUTCOME_API_KEY=oc_agent_REDACTED \
OUTCOME_ACCEPTANCE_POLICY_ID=... \
OUTCOME_ACCEPTANCE_VERIFICATION_RESULT_ID=... \
OUTCOME_ACCEPTANCE_ENV=controlled-beta \
OUTCOME_ACCEPTANCE_REPORT=artifacts/beta-acceptance.json \
.venv/bin/python -m tools.acceptance.outcome_acceptance
```

Do not put secrets in shell history in a real environment; inject them from the operator secret mechanism.

## Report and pass gate

The versioned JSON report contains service/tool/schema versions, environment, safe authorization/billing/settlement/receipt IDs and amounts, evidence score, validation outcomes, durations, reason codes, and overall PASS/FAIL. It excludes the API key, signing material, raw evidence, provider credentials, action payload, Stripe data, and infrastructure URLs.

PASS is unweighted and requires discovery, compatibility, auth rejection checks, ALLOW, one settlement with charge ≤ reserve, receipt issuance, exact-action consumption, changed-action rejection, consumed-receipt rejection, stable idempotent replay, conflict rejection, and no detected secret leakage.

External verification is structural. Cryptographic verification is truthfully reported as `SERVER_EXECUTION_BOUNDARY_PASS`: the private key stays server-side and the execution boundary verifies the signature before consumption. Outcome does not claim client-side cryptographic validation or expose private keys.

## Failure triage

Use `failed_stage`, stable `reason_codes`, safe request IDs, and `remediation_hint`. Common fixes are endpoint/tool version alignment, key scope correction, policy/verification fixture correction, prepaid funding, Redis availability, or receipt-key configuration. Default output has no stack trace. Correlate MCP audit events with the authorization request ID, verification result ID, billing ID, settlement transaction ID, and receipt ID from the report.

## Cleanup and security limitations

For local cleanup, stop the Compose project with `docker compose down`; add `-v` only when intentionally deleting local test data. Remote operators should revoke the key and retire the dedicated fixture account/policy according to retention rules. No public bypass, money-mint, policy-admin, receipt-sign/reset, generic fetch, arbitrary provider, or arbitrary execution endpoint exists. The validation tool consumes receipts but performs no action.

## First real independent agent

1. Deploy controlled-beta Outcome.
2. Create a dedicated low-value beta account.
3. Issue a least-privilege API key.
4. Provision a small prepaid test balance.
5. Configure the narrow safe policy.
6. Connect an independently developed MCP-capable agent/client.
7. Give it only Outcome's MCP endpoint and credential.
8. Let it discover tools itself.
9. Ask it to perform the safe authorization workflow.
10. Capture the acceptance report and operational logs.
11. Record every friction point and failure.
12. Fix reality-derived issues before speculative features.
