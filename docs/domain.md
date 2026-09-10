# Domain Notes

Provider and system failure statuses are operational states. `PROVIDER_FAILED` and
`SYSTEM_FAILURE` must never be interpreted as claim contradiction.

Only `CONTRADICTED` means the verification result conflicts with the claim.
