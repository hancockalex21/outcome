# Outcome controlled-beta quickstart

Outcome decides whether an agent may perform one exact material action and, on `ALLOW`, returns a
signed receipt bound to that action. Outcome does not execute the action; this quickstart uses a
zero-value synthetic test with no external side effect.

Time to first authorization: about five minutes.

> **Security: Never paste an `oc_agent_*` credential into chat, GitHub, logs, screenshots,
> tickets, or documentation.** Treat it like a production password.

## Prerequisites

- A controlled-beta invite token, delivered privately by the Outcome team. The beta is
  invitation-only: ask the person or team who shared this guide for access. Never post the invite
  token in a public request.
- `curl`, `jq`, `openssl`, and [Codex CLI](https://developers.openai.com/codex/extend/mcp).
- Bash on macOS or Linux. Run `bash` first if needed, then run Codex from that same shell so it
  inherits the credential.

The invite token only permits registration. It is not the agent credential used with MCP.

## 1. Register and capture the one-time credential

Read the invite without putting it in shell history, create a protected temporary response file,
and register:

```bash
read -rsp "Outcome beta invite token: " OUTCOME_BETA_INVITE_TOKEN && printf '\n'
umask 077
OUTCOME_REGISTRATION_RESPONSE="$(mktemp "${TMPDIR:-/tmp}/outcome-registration.XXXXXX")"
trap 'rm -f "$OUTCOME_REGISTRATION_RESPONSE"' EXIT

curl --fail-with-body --silent --show-error \
  --request POST 'https://outcome-api-hyqe.onrender.com/v1/beta/register' \
  --header 'Content-Type: application/json' \
  --header "X-Outcome-Beta-Token: ${OUTCOME_BETA_INVITE_TOKEN}" \
  --header "Idempotency-Key: quickstart-$(openssl rand -hex 16)" \
  --data '{"display_name":"My Outcome beta agent"}' \
  --output "$OUTCOME_REGISTRATION_RESPONSE"

unset OUTCOME_BETA_INVITE_TOKEN
export OUTCOME_AGENT_API_KEY="$(jq -er '.agent_api_key' "$OUTCOME_REGISTRATION_RESPONSE")"
jq '{credential_scopes, mcp_endpoint, promotional_credit_micro_usd,
     promotional_credit_classification, starter_policy, capabilities_tool}' \
  "$OUTCOME_REGISTRATION_RESPONSE"
rm -f "$OUTCOME_REGISTRATION_RESPONSE"
trap - EXIT
```

`agent_api_key` is shown only in the first successful registration response. The commands above
keep it out of the terminal display and export it only to the current shell; they do not write it
to a shell profile or repository. Store it in your normal password manager or secret manager if
you need it after this shell exits.

An exact retry cannot reveal the credential again. If the response is lost, registration returns
`409 credential recovery required` without creating a second account or promotional credit; ask
the Outcome operator to revoke the inaccessible credential.

The `1,000,000` micro-USD promotional balance is controlled-beta test credit. It is not a customer
payment and is not revenue.

## 2. Connect Codex to Outcome

Configure the hosted Streamable HTTP server using the environment variable—not the credential
itself—and confirm the entry:

```bash
codex mcp add outcome \
  --url 'https://outcome-mcp.onrender.com/mcp' \
  --bearer-token-env-var OUTCOME_AGENT_API_KEY
codex mcp list
```

This stores the environment variable's **name** in Codex configuration, not its value. Start a new
Codex session from this same shell after adding the server. If Codex was already open, restart it;
an existing process may not see the newly exported variable.

## 3. Discover Outcome

In the new Codex session, enter:

```text
Call Outcome's outcome_capabilities tool. Summarize its authorization workflow and receipt
semantics. Do not call any other Outcome tool yet.
```

You should see `outcome_authorize`, `STANDARD` assurance, tenant-local policy resolution, prepaid
billing, and signed receipts that do not execute actions.

## 4. Authorize the synthetic starter action

In the same Codex session, enter the prompt below. Codex must replace the expiry instruction with
an RFC 3339 UTC timestamp no more than five minutes in the future and then pass the resulting JSON
as the `outcome_authorize` tool argument:

```text
Call Outcome's outcome_authorize tool exactly once with the following argument. Set
request.authorization_expires_at to the current UTC time plus five minutes. Do not add policy_id,
policy_version, verification_result_id, verification_claim, or verification_subject.

{
  "request": {
    "idempotency_key": "quickstart-authorization-REPLACE-WITH-A-NEW-RANDOM-VALUE",
    "requested_assurance": "STANDARD",
    "authorization_expires_at": "REPLACE-WITH-NOW-PLUS-FIVE-MINUTES-IN-RFC3339-UTC",
    "verification_required": false,
    "action": {
      "action_schema_version": "action.material.v1",
      "name": "controlled_beta_test",
      "target": "synthetic-resource",
      "material": {
        "action_type": "controlled_beta_test",
        "capability": "authorize",
        "amount_micro_usd": 0,
        "currency": "USD",
        "destination": "synthetic-resource",
        "resource": "quickstart-demo"
      },
      "ephemeral": {}
    }
  }
}
```

Use a fresh random idempotency value. Reusing the same value with changed input fails closed as an
idempotency conflict. No `policy_id` is needed because registration creates exactly one applicable
tenant policy; no verification input is needed because this starter action sets
`verification_required` to `false`.

## 5. Confirm `ALLOW`

A successful tool response has this shape (identifiers, hashes, timestamps, receipt contents, and
billing details vary):

```json
{
  "ok": true,
  "error_code": null,
  "data": {
    "decision": "ALLOW",
    "authorization_request_id": "...",
    "authorization_result_id": "...",
    "policy_id": "...",
    "policy_version": 1,
    "action_hash": "...",
    "receipt_id": "...",
    "signed_receipt": { "...": "..." },
    "reason_codes": ["POLICY_ALLOWED"]
  }
}
```

The signed receipt proves that Outcome authorized the exact material action under the selected
policy until the receipt expires. Changing the action invalidates that binding. The receipt does
not perform the synthetic action—or any other action—and this quickstart intentionally has no
external side effect.

## Common errors

- Registration `401`: the invite token is missing or invalid.
- Registration `409 idempotency conflict`: that registration key was reused with different input.
- Registration `409 credential recovery required`: registration succeeded earlier, but its
  one-time credential cannot be replayed.
- Registration `429`: the per-client rate limit or controlled-beta capacity was reached.
- `AUTHENTICATION_FAILED`: Codex did not inherit `OUTCOME_AGENT_API_KEY`, or the credential was
  revoked. Restart Codex from the exporting shell; never paste the key into chat.
- `INSUFFICIENT_SCOPE`: the credential lacks `authorize:write`.
- `VALIDATION_FAILED`: a required field, timestamp, or schema value is invalid.
- `IDEMPOTENCY_CONFLICT`: the authorization key was reused with changed input; use a new key.
- `NO_APPLICABLE_POLICY`: the material action does not match the starter policy exactly.
- `AMBIGUOUS_POLICY`: more than one tenant policy matched; fail closed and contact the operator.
- `INSUFFICIENT_FUNDS`: no prepaid test credit remains.
- `BLOCK`, `RETRY_HIGHER_ASSURANCE`, or `ESCALATE`: do not execute anything; follow the response's
  recovery guidance.

## Remove local access after testing

Close Codex, remove the MCP entry if you no longer need it, clear the current shell variable, and
close the shell:

```bash
codex mcp remove outcome
unset OUTCOME_AGENT_API_KEY
```

Also delete any password-manager entry or temporary copy you intentionally created. Clearing a
local copy does not revoke the server-side credential; contact the Outcome operator if it was
lost or exposed.

## Success

You are done when `outcome_capabilities` was discovered through standard MCP and
`outcome_authorize` returned `ok: true`, `decision: ALLOW`, and a non-null `signed_receipt` for the
zero-value `controlled_beta_test`. You have proven that your independently registered agent can
authenticate, resolve its tenant-local starter policy, purchase an authorization with promotional
test credit, and receive a signed action-bound authorization—without executing an external action.
