from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from outcome.actions import (
    ACTION_SCHEMA_VERSION,
    ActionBindingContext,
    CanonicalizationError,
    action_hash,
    canonical_action_binding_json,
    normalize_utc_timestamp,
)
from outcome.schemas.v1 import AuthorizeAction

ACCOUNT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ACCOUNT_ID = UUID("22222222-2222-4222-8222-222222222222")
EXPIRY = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=UTC)
BASE_MATERIAL = {
    "merchant": "example-market",
    "amount_micro_usd": 12_500_000,
    "currency": "USD",
    "destination": "acct_merchant_123",
    "sku": "verification-standard",
}
EXPECTED_CANONICAL_BINDING = (
    '{"binding":{"account_id":"11111111-1111-4111-8111-111111111111",'
    '"action_schema_version":"action.material.v1",'
    '"authorization_expires_at":"2026-09-10T12:00:00.123456Z",'
    '"policy_version":"policy-v1"},"canonical_material_action":"{\\"action_schema_version\\":'
    '\\"action.material.v1\\",\\"material\\":{\\"amount_micro_usd\\":12500000,'
    '\\"currency\\":\\"USD\\",\\"destination\\":\\"acct_merchant_123\\",'
    '\\"merchant\\":\\"example-market\\",\\"sku\\":\\"verification-standard\\"}}"}'
)
EXPECTED_ACTION_HASH = "0dec498922c309d952bd398ec020c25e3ce037c5bb9972fad2e41232e90b09df"


def binding_context(
    *,
    account_id: UUID = ACCOUNT_ID,
    policy_version: str = "policy-v1",
    action_schema_version: str = ACTION_SCHEMA_VERSION,
    authorization_expires_at: datetime = EXPIRY,
) -> ActionBindingContext:
    return ActionBindingContext(
        account_id=account_id,
        policy_version=policy_version,
        action_schema_version=action_schema_version,
        authorization_expires_at=authorization_expires_at,
    )


def test_stable_action_hash_vector() -> None:
    context = binding_context()

    assert canonical_action_binding_json(
        material=BASE_MATERIAL,
        binding_context=context,
    ) == EXPECTED_CANONICAL_BINDING
    assert action_hash(material=BASE_MATERIAL, binding_context=context) == EXPECTED_ACTION_HASH


def test_identical_action_and_binding_context_hash_identically() -> None:
    context = binding_context()

    assert action_hash(material=BASE_MATERIAL, binding_context=context) == action_hash(
        material=dict(BASE_MATERIAL),
        binding_context=context,
    )


def test_json_key_ordering_does_not_affect_hash() -> None:
    reordered = {
        "sku": "verification-standard",
        "destination": "acct_merchant_123",
        "currency": "USD",
        "amount_micro_usd": 12_500_000,
        "merchant": "example-market",
    }

    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) == action_hash(
        material=reordered,
        binding_context=binding_context(),
    )


def test_ephemeral_timestamp_request_id_and_nonce_do_not_affect_hash() -> None:
    first = AuthorizeAction(
        name="purchase",
        target="merchant:example-market",
        material=BASE_MATERIAL,
        ephemeral={"timestamp": "2026-09-10T00:00:00Z", "request_id": "one", "nonce": "a"},
    )
    second = AuthorizeAction(
        name="purchase",
        target="merchant:example-market",
        material=BASE_MATERIAL,
        ephemeral={"timestamp": "2026-09-10T00:01:00Z", "request_id": "two", "nonce": "b"},
    )

    assert first.action_hash(binding_context()) == second.action_hash(binding_context())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("amount_micro_usd", 12_500_001),
        ("merchant", "different-market"),
        ("destination", "acct_merchant_456"),
        ("sku", "verification-high"),
    ],
)
def test_material_change_changes_hash(field: str, value: object) -> None:
    changed = dict(BASE_MATERIAL)
    changed[field] = value

    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) != action_hash(
        material=changed,
        binding_context=binding_context(),
    )


def test_binding_account_id_change_changes_hash() -> None:
    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) != action_hash(
        material=BASE_MATERIAL,
        binding_context=binding_context(account_id=OTHER_ACCOUNT_ID),
    )


def test_binding_policy_version_change_changes_hash() -> None:
    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) != action_hash(
        material=BASE_MATERIAL,
        binding_context=binding_context(policy_version="policy-v2"),
    )


def test_binding_action_schema_version_change_changes_hash() -> None:
    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) != action_hash(
        material=BASE_MATERIAL,
        binding_context=binding_context(action_schema_version="action.material.v2"),
    )


def test_binding_authorization_expiry_change_changes_hash() -> None:
    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) != action_hash(
        material=BASE_MATERIAL,
        binding_context=binding_context(authorization_expires_at=EXPIRY + timedelta(seconds=1)),
    )


def test_equivalent_utc_timestamps_canonicalize_identically() -> None:
    equivalent = datetime(
        2026,
        9,
        10,
        7,
        0,
        0,
        123456,
        tzinfo=timezone(timedelta(hours=-5)),
    )

    assert normalize_utc_timestamp(EXPIRY) == normalize_utc_timestamp(equivalent)
    assert action_hash(material=BASE_MATERIAL, binding_context=binding_context()) == action_hash(
        material=BASE_MATERIAL,
        binding_context=binding_context(authorization_expires_at=equivalent),
    )


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        action_hash(
            material=BASE_MATERIAL,
            binding_context=binding_context(
                authorization_expires_at=datetime(2026, 9, 10, 12, 0, 0),
            ),
        )


def test_unsupported_and_ambiguous_material_values_remain_rejected() -> None:
    with pytest.raises(CanonicalizationError):
        action_hash(material={"amount": 1.1}, binding_context=binding_context())
    with pytest.raises(CanonicalizationError):
        action_hash(material={"amount": object()}, binding_context=binding_context())


def test_no_secret_values_are_included() -> None:
    canonical = canonical_action_binding_json(
        material=BASE_MATERIAL,
        binding_context=binding_context(),
    )

    assert "api_key" not in canonical
    assert "authorization_header" not in canonical
    assert "Bearer " not in canonical
    assert "nonce" not in canonical
    assert str(uuid4()) not in canonical
