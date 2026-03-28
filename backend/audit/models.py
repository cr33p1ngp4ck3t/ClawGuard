from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    POLICY_BLOCK = "policy_block"
    INJECTION_DETECTED = "injection_detected"
    INJECTION_BLOCKED = "injection_blocked"


class ProxyRequest(BaseModel):
    target_url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict | str | None = None
    agent_id: str = "unknown"
    tool_name: str = "unknown"


class ProxyResponse(BaseModel):
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | dict = ""
    blocked: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    threats_detected: list[str] = Field(default_factory=list)
    policy_rule: str | None = None


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    agent_id: str
    tool_name: str
    event_type: EventType
    risk_level: RiskLevel
    target_url: str
    request_summary: str = ""
    response_summary: str | None = None
    blocked: bool = False
    detection_details: dict | None = None
    policy_rule: str | None = None
    duration_ms: int = 0


class DetectionResult(BaseModel):
    is_threat: bool
    risk_level: RiskLevel
    matched_patterns: list[str] = Field(default_factory=list)
    llm_explanation: str | None = None
    confidence: float = 0.0
    scan_duration_ms: int = 0


class PatternMatch(BaseModel):
    pattern_name: str
    matched_text: str
    severity: RiskLevel
    position: int = 0


class DashboardStats(BaseModel):
    total_requests: int = 0
    blocked_requests: int = 0
    threats_detected: int = 0
    risk_breakdown: dict[str, int] = Field(default_factory=dict)
    avg_latency_ms: float = 0.0
