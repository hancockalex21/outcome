from __future__ import annotations

import math

import pytest

from outcome.actions import (
    ACTION_SCHEMA_VERSION,
    CanonicalizationError,
    material_action_hash,
)
from outcome.schemas.v1 import AuthorizeAction

BASE_MATERIAL = {
    "merchant": "example-market",
    "amount_micro_usd": 12_500_000,
    "currency": "USD",
    "destination": "acct_merchant_123",
    "sku": "verification-standard",
}


def test_equivalent_material_json_hashes_identically() -> None:
    first = {
        "currency": "USD",
        "sku": "verification-standard",
        "amount_micro_usd": 12_500_000,
        "destination": "acct_merchant_123",
        "merchant": "example-market",
    }
    second = {
        "merchant": "example-market",
        "amount_micro_usd": 12500000,
        "currency": "USD",
        "destination": "acct_merchant_123",
        "sku": "verification-standard",
    }

    assert material_action_hash(material=first) == material_action_hash(material=second)


def test_ephemeral_timestamp_and_nonce_do_not_change_material_hash() -> None:
    first = AuthorizeAction(
        name="purchase",
        target="merchant:example-market",
        material=BASE_MATERIAL,
        ephemeral={"timestamp": "2026-09-10T00:00:00Z", "nonce": "one"},
    )
    second = AuthorizeAction(
        name="purchase",
        target="merchant:example-market",
        material=BASE_MATERIAL,
        ephemeral={"timestamp": "2026-09-10T00:01:00Z", "nonce": "two"},
    )

    assert first.material_hash() == second.material_hash()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("merchant", "different-market"),
        ("amount_micro_usd", 12_500_001),
        ("currency", "EUR"),
        ("destination", "acct_merchant_456"),
        ("sku", "verification-high"),
        ("metadata", {"purchase_order": "PO-1"}),
    ],
)
def test_material_changes_always_change_hash(field: str, value: object) -> None:
    changed = dict(BASE_MATERIAL)
    changed[field] = value

    assert material_action_hash(material=BASE_MATERIAL) != material_action_hash(material=changed)


def test_schema_version_is_bound() -> None:
    assert (
        material_action_hash(
            material=BASE_MATERIAL,
            action_schema_version=ACTION_SCHEMA_VERSION,
        )
        != material_action_hash(
            material=BASE_MATERIAL,
            action_schema_version="action.material.v2",
        )
    )


@pytest.mark.parametrize("value", [1.1, math.nan, math.inf, -math.inf])
def test_float_nan_and_infinity_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        material_action_hash(material={"amount": value})


def test_ambiguous_large_integer_is_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        material_action_hash(material={"amount": 9_007_199_254_740_992})


def test_unsupported_types_are_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        material_action_hash(material={"amount": object()})
