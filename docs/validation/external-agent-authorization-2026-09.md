# External standard-agent authorization validation — September 2026

## Scope and result

An operator configured a fresh Codex CLI agent with Outcome's production Render-hosted
streamable-HTTP MCP service, a scoped bearer credential, and the controlled-beta identifiers.
Without a custom Outcome client or repository access, the agent discovered Outcome through
MCP, called `outcome_capabilities`, decided authorization was appropriate, constructed and
submitted the request, authenticated, and received `PolicyDecision.ALLOW` plus a signed,
action-bound receipt. The harmless underlying action was intentionally not executed and the
receipt was intentionally not consumed.

This validates the path:

`standard MCP client → discovery → agent-selected authorization → ALLOW → signed receipt`

It also validates standard MCP bearer authentication and Codex deferred discovery once
Outcome is relevant. Machine-readable discovery was effective.

## Earlier failures and lessons

Earlier attempts exposed onboarding dependencies rather than authorization defects:

- `policy_id` and `verification_result_id` had to be transferred out of band.
- Ordinary shell environment variables were not automatically visible in the agent/tool
  context, so the MCP client's own secret/header configuration had to carry authentication.
- Deferred MCP discovery required Outcome to be made relevant to the task.

The result does **not** establish product-market fit, organic demand, external action
execution, receipt consumption, real-world verification accuracy, self-service onboarding,
or paid demand. The operator configured the integration and supplied required identifiers.

## Resulting product changes

- Authorization can omit policy identifiers when exactly one currently effective published
  policy matches inside the authenticated tenant. No match or ambiguity fails closed.
- Authorization can submit a bounded verification claim and subject; the existing
  `VerificationOrchestrator` produces the result internally. Explicit tenant-owned result IDs
  remain compatible for controlled beta.
- Capability discovery now explains selection, verification, decision recovery, receipt
  non-execution/consumption, and safe billing behavior.
- A repository-independent external MCP quickstart now documents the shortest safe path.

No policy, evidence, tenant, receipt, billing, or credential security invariant was relaxed.
