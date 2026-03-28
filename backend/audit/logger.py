from __future__ import annotations

from audit.db import insert_event
from audit.models import AuditEvent
from api.ws import manager


async def log_event(event: AuditEvent) -> None:
    event_dict = event.model_dump()
    await insert_event(event_dict)
    await manager.broadcast({"type": "new_event", "payload": event_dict})
