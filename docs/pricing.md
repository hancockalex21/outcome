# Pricing

Pricing uses integer microdollars for all persisted and internal money values. One
microdollar is one millionth of one US dollar. Binary floating-point values must not be
used for money.

Each published capability pricing configuration has an immutable
`pricing_config_version`. Updating pricing rules creates a new version.

For managed capabilities, expected Outcome-side cost includes compute cost, managed
supplier cost, retry reserve, and operational allocation. For BYOK capabilities,
customer-paid supplier cost is excluded from Outcome cost of goods sold, but Outcome
compute, retry reserve, and operational allocation remain included.

The margin-protected price is rounded up using integer ceiling division:

`ceil(expected_total_cost_micro_usd * 10000 / (10000 - target_gross_margin_bps))`

The final quoted price is the greater of the configured minimum price and the
margin-protected price.
