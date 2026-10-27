"""Detection-only endpoint — scans content without forwarding."""
from __future__ import annotations

import asyncio
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from auth import bind_agent, require_agent

from detection.engine import analyze_content

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    content: str = Field(max_length=512 * 1024)
    agent_id: str = Field(default="unknown", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    tool_name: str = Field(default="unknown", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")


class ScanResponse(BaseModel):
    is_threat: bool
    risk_level: str
    matched_patterns: list[str]
    confidence: float
    scan_duration_ms: int


@router.post("/scan", response_model=ScanResponse)
async def scan_content(req: ScanRequest, agent: str = Depends(require_agent)) -> ScanResponse:
    agent = bind_agent(req.agent_id, agent)
    try:
        async with asyncio.timeout(5):
            result = await analyze_content(content=req.content, agent_id=agent, tool_name=req.tool_name)
    except Exception as exc:
        raise HTTPException(503, "Content scanner unavailable") from exc
    return ScanResponse(
        is_threat=result.is_threat,
        risk_level=result.risk_level.value,
        matched_patterns=result.matched_patterns,
        confidence=result.confidence,
        scan_duration_ms=result.scan_duration_ms,
    )
