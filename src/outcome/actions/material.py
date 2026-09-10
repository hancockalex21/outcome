from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Literal

ACTION_SCHEMA_VERSION: Literal["action.material.v1"] = "action.material.v1"
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
MIN_SAFE_JSON_INTEGER = -MAX_SAFE_JSON_INTEGER


class CanonicalizationError(ValueError):
    pass


def material_action_hash(
    *,
    material: Mapping[str, object],
    action_schema_version: str = ACTION_SCHEMA_VERSION,
) -> str:
    canonical = canonical_material_json(
        material=material,
        action_schema_version=action_schema_version,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def canonical_material_json(
    *,
    material: Mapping[str, object],
    action_schema_version: str = ACTION_SCHEMA_VERSION,
) -> str:
    normalized = {
        "action_schema_version": _normalize_schema_version(action_schema_version),
        "material": _normalize_value(material),
    }
    return json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _normalize_schema_version(action_schema_version: str) -> str:
    if not action_schema_version:
        raise CanonicalizationError("action_schema_version is required")
    return action_schema_version


def _normalize_value(value: object) -> object:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_SAFE_JSON_INTEGER <= value <= MAX_SAFE_JSON_INTEGER:
            raise CanonicalizationError("integer is outside the safe canonical JSON range")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floating-point JSON numbers are not accepted")
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            normalized[key] = _normalize_value(nested_value)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize_value(item) for item in value]
    raise CanonicalizationError(f"unsupported material value type: {type(value).__name__}")
