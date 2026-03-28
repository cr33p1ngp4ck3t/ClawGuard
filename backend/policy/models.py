from __future__ import annotations

from pydantic import BaseModel, Field


class ToolPermission(BaseModel):
    tool_name: str
    allowed: bool
    conditions: dict | None = None


class NetworkRule(BaseModel):
    pattern: str
    action: str  # "allow" | "deny"
    reason: str


class Policy(BaseModel):
    name: str
    version: str = "1.0"
    agent_rules: dict[str, list[ToolPermission]] = Field(default_factory=dict)
    network_rules: list[NetworkRule] = Field(default_factory=list)
    max_response_size_kb: int = 1024
