from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class BetaRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    display_name: Annotated[str, Field(min_length=1, max_length=100)]


class StarterPolicySummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: UUID
    version: int
    action_type: Literal["controlled_beta_test"] = "controlled_beta_test"
    destination: Literal["synthetic-resource"] = "synthetic-resource"
    maximum_amount_micro_usd: Literal[0] = 0


class BetaRegistrationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    registration_id: UUID
    account_id: UUID
    agent_id: UUID
    agent_api_key: str
    credential_scopes: tuple[str, ...]
    mcp_endpoint: str
    promotional_credit_micro_usd: int
    promotional_credit_classification: Literal["PROMOTIONAL_NOT_REVENUE"] = (
        "PROMOTIONAL_NOT_REVENUE"
    )
    starter_policy: StarterPolicySummary
    capabilities_tool: Literal["outcome_capabilities"] = "outcome_capabilities"
    quickstart_url: str | None = None
