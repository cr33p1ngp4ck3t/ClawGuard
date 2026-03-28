from __future__ import annotations

from fastapi import APIRouter

from audit.db import get_stats, query_events

router = APIRouter(prefix="/api")


@router.get("/events")
async def list_events(
    limit: int = 50,
    offset: int = 0,
    risk_level: str | None = None,
    agent_id: str | None = None,
):
    events = await query_events(
        limit=limit, offset=offset, risk_level=risk_level, agent_id=agent_id
    )
    return {"events": events, "count": len(events)}


@router.get("/stats")
async def dashboard_stats():
    return await get_stats()


@router.get("/policy")
async def active_policy():
    from main import app_policy

    return app_policy.model_dump()
