# Ledger

Outcome stores prepaid credit money as signed integer microdollars.

One internal unit is one millionth of one US dollar. The canonical persisted field is
`credit_ledger_entries.amount_micro_usd`. Binary floating-point values must never be
used for persisted money.

The customer credit balance is derived from double-entry ledger rows, not from a mutable
account balance field. For customer-facing prepaid credits:

- credits to `customer_prepaid_liability` increase available customer credits
- debits to `customer_prepaid_liability` decrease available customer credits

Corrections must be represented as reversing or adjustment entries. Historical ledger
rows are append-only through `LedgerService`.
