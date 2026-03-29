"""ClawGuard SDK data types."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ProxyResult(BaseModel):
    """Result from the /proxy endpoint."""
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | dict = ""
    blocked: bool = False
    risk_level: str = "low"
    threats_detected: list[str] = Field(default_factory=list)
    policy_rule: str | None = None


class ScanResult(BaseModel):
    """Result from the /api/scan endpoint."""
    is_threat: bool
    risk_level: str
    matched_patterns: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    scan_duration_ms: int = 0
