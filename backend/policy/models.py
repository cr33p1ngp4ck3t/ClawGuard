from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from policy.urls import origin, parse_target


class ToolPermission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    allowed: bool


class NetworkRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pattern: str
    action: Literal["deny"]
    reason: str


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str = "1.0"
    agent_rules: dict[str, list[ToolPermission]] = Field(default_factory=dict)
    network_rules: list[NetworkRule] = Field(default_factory=list)
    allowed_origins: dict[str, list[str]] = Field(default_factory=dict)
    allowed_methods: dict[str, list[Literal["GET", "HEAD", "POST"]]] = Field(default_factory=dict)
    max_response_size_kb: int = Field(default=512, ge=1, le=1024)

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, values: dict[str, list[str]]) -> dict[str, list[str]]:
        for agent, origins in values.items():
            canonical = []
            for value in origins:
                url = parse_target(value)
                if url.path not in ("", "/") or url.query:
                    raise ValueError("Allowed origins cannot include paths or queries")
                canonical.append(origin(url))
            values[agent] = canonical
        return values
