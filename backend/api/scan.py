"""Detection-only endpoint — scans content without forwarding."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from detection.engine import analyze_content

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    content: str
    agent_id: str = "unknown"
    tool_name: str = "unknown"


class ScanResponse(BaseModel):
    is_threat: bool
    risk_level: str
    matched_patterns: list[str]
    confidence: float
    scan_duration_ms: int


@router.post("/scan", response_model=ScanResponse)
async def scan_content(req: ScanRequest) -> ScanResponse:
    result = await analyze_content(
        content=req.content,
        agent_id=req.agent_id,
        tool_name=req.tool_name,
    )
    return ScanResponse(
        is_threat=result.is_threat,
        risk_level=result.risk_level.value,
        matched_patterns=result.matched_patterns,
        confidence=result.confidence,
        scan_duration_ms=result.scan_duration_ms,
    )
