# External MCP quickstart

Outcome verifies bounded claims and decides whether one exact material action may proceed.
It never performs the underlying action. An `ALLOW` response may contain a signed,
short-lived receipt bound to exactly the submitted material action.

## 1. Register for the controlled beta

The operator supplies a beta invite token and public API URL. The invite is bootstrap
authorization only; it is not an Outcome agent credential. Register once:

```bash
curl --fail-with-body -X POST 'https://PUBLIC_OUTCOME_API/v1/beta/register' \
  -H 'Content-Type: application/json' \
  -H 'X-Outcome-Beta-Token: BETA_INVITE_REDACTED' \
  -H 'Idempotency-Key: registration-UNIQUE_RANDOM_VALUE' \
  --data '{"display_name":"Example Developer"}'
```

The response contains the MCP endpoint, one `authorize:write` `oc_agent_*` credential, starter
policy summary, and promotional balance. Promotional credit is service credit, not customer-paid
balance or revenue. Store the agent credential immediately: it is returned only in the first
successful response. A retry after a lost response creates nothing new and returns a
recovery-required conflict. Contact the operator to revoke and replace the inaccessible key.

## 2. Configure the remote MCP server

Use the public hosted MCP URL supplied during beta onboarding. A standard remote-MCP
configuration has this shape; adapt the field names to the client and use its secret-header
facility rather than a literal value:

```json
{
  "mcpServers": {
    "outcome": {
      "type": "streamable-http",
      "url": "https://PUBLIC_OUTCOME_HOST/mcp",
      "headers": {
        "Authorization": "Bearer oc_agent_REDACTED"
      }
    }
  }
}
```

Some agent sandboxes do not inherit ordinary shell environment variables. Confirm that the
client actually resolves its secret reference inside the MCP transport context. Never put a
real token in a committed file; the literal above is intentionally invalid.

## 3. Discover before calling

Ask the agent to call `outcome_capabilities`. It describes when to verify or authorize,
assurance levels, decisions, policy selection, verification inputs, billing, receipts, and
recovery behavior. Tool schemas are also available through standard MCP discovery.

## 4. Authorize the starter action

Use a unique idempotency key and an expiry no more than five minutes in the future. This
example asks Outcome to resolve one applicable policy inside the authenticated tenant and
authorize its deliberately limited zero-value synthetic action:

```json
{
  "request": {
    "idempotency_key": "quickstart-demo-001",
    "requested_assurance": "STANDARD",
    "authorization_expires_at": "2026-12-01T12:05:00Z",
    "verification_required": false,
    "action": {
      "action_schema_version": "action.material.v1",
      "name": "controlled_beta_test",
      "target": "synthetic-resource",
      "material": {
        "action_type": "controlled_beta_test",
        "capability": "authorize",
        "amount_micro_usd": 0,
        "destination": "synthetic-resource",
        "resource": "quickstart-demo"
      },
      "ephemeral": {}
    }
  }
}
```

If a later onboarding flow supplies an explicit policy, include both `policy_id` and
`policy_version`.
If it supplies an existing verification result, use `verification_result_id` instead of the
claim and subject. Result IDs are checked against the authenticated tenant; clients cannot
submit a verification status or score. Hosted claim-based verification requires an approved
provider configuration; without one it safely returns a non-verified outcome.

## 5. Interpret the decision

- `ALLOW`: the exact action is authorized until receipt expiry. This still does not execute it.
- `BLOCK`: do not execute. Correct the action, policy, or evidence issue before a new request.
- `RETRY_HIGHER_ASSURANCE`: retry at the required assurance using a new idempotency key.
- `ESCALATE`: do not execute; send the case to the configured review path.

Transport/tool errors also fail closed. `NO_APPLICABLE_POLICY` means no tenant-local policy
matched. `AMBIGUOUS_POLICY` means more than one matched; select an explicit policy or ask the
operator to make routing unambiguous.

## 6. Validate at the execution boundary (optional)

Immediately before performing the action, call `outcome_execute_authorized` with a new
`execution_request_id`, the returned `signed_receipt`, `action.material` unchanged, and its
schema version. Outcome verifies the signature, tenant, expiry, and exact action binding and
consumes a valid receipt once. The call validates authorization; it does not execute the
action. A changed action, expired receipt, other tenant, or second consumption fails closed.

Authorization is prepaid in integer micro-USD. A stable idempotent replay reuses the original
result and does not charge twice. Insufficient balance fails closed.
