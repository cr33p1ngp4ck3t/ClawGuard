from __future__ import annotations

import asyncio
import logging
import time

from audit.logger import log_event
from audit.models import AuditEvent, EventType, ProxyRequest, ProxyResponse, RiskLevel
from detection.engine import analyze_content
from policy.engine import evaluate_request
from policy.models import Policy
from proxy.client import ForwardBlocked, forward_request

logger = logging.getLogger('clawguard.proxy')


async def handle_proxy_request(request: ProxyRequest, policy: Policy) -> ProxyResponse:
    start = time.monotonic()
    event_type = EventType.POLICY_BLOCK
    try:
        decision = await evaluate_request(request.target_url, request.agent_id, request.tool_name, policy, request.method)
        if not decision.allowed:
            response = ProxyResponse(status_code=403, body={'error': decision.reason}, blocked=True,
                                     risk_level=RiskLevel.CRITICAL, policy_rule=decision.reason,
                                     threats_detected=[decision.reason])
        else:
            status, headers, body = await forward_request(
                request.target_url, request.method, request.headers, request.body,
                addresses=decision.addresses, max_bytes=policy.max_response_size_kb * 1024,
            )
            async with asyncio.timeout(5):
                detection = await analyze_content(body, request.agent_id, request.tool_name)
            blocked = detection.is_threat and detection.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            event_type = EventType.INJECTION_BLOCKED if blocked else EventType.RESPONSE
            response = ProxyResponse(
                status_code=status, headers=headers if not blocked else {},
                body={'warning': 'Response blocked: possible prompt injection'} if blocked else body,
                blocked=blocked, risk_level=detection.risk_level,
                threats_detected=detection.matched_patterns,
            )
    except ForwardBlocked as exc:
        response = ProxyResponse(status_code=422, body={'error': str(exc)}, blocked=True,
                                 risk_level=RiskLevel.HIGH, policy_rule=str(exc))
    except Exception:
        # Do not log upstream exceptions: they can contain credentials or URL queries.
        logger.warning('Gateway enforcement failed; response withheld')
        event_type = EventType.REQUEST
        response = ProxyResponse(status_code=503, body={'error': 'Gateway could not safely complete the request'},
                                 blocked=True, policy_rule='Gateway enforcement unavailable')
    await log_event(AuditEvent(
        agent_id=request.agent_id, tool_name=request.tool_name, event_type=event_type,
        risk_level=response.risk_level, target_url=request.target_url, blocked=response.blocked,
        policy_rule=response.policy_rule, duration_ms=int((time.monotonic() - start) * 1000),
        detection_details={'patterns': response.threats_detected} if event_type == EventType.INJECTION_BLOCKED else None,
    ))
    return response
