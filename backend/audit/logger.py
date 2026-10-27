from __future__ import annotations

from audit.db import insert_event
from audit.models import AuditEvent
from audit.redaction import redact_event
from api.ws import manager
import logging

logger = logging.getLogger("clawguard.audit")


async def log_event(event: AuditEvent) -> None:
    event_dict = redact_event(event.model_dump())
    await insert_event(event_dict)
    logger.info("decision event=%s blocked=%s agent=%s", event.event_type.value, event.blocked, event.agent_id)
    await manager.broadcast({"type": "new_event", "payload": event_dict})
