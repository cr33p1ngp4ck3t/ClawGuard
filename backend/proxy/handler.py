from __future__ import annotations

import logging
import time

from audit.logger import log_event
from audit.models import AuditEvent, EventType, ProxyRequest, ProxyResponse, RiskLevel
from detection.engine import analyze_content
from policy.engine import PolicyDecision, evaluate_request
from policy.models import Policy
from proxy.client import forward_request

logger = logging.getLogger("clawguard.proxy")


async def handle_proxy_request(
    request: ProxyRequest, policy: Policy
) -> ProxyResponse:
    """Core proxy pipeline: policy check -> forward -> scan response -> return/block."""
    start = time.time()

    # --- Step 1: Policy check (before forwarding) ---
    decision = await evaluate_request(
        target_url=request.target_url,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        policy=policy,
    )

    if not decision.allowed:
        elapsed = int((time.time() - start) * 1000)
        response = ProxyResponse(
            status_code=403,
            body={"error": "Blocked by policy", "reason": decision.reason},
            blocked=True,
            risk_level=RiskLevel.CRITICAL,
            threats_detected=[decision.reason],
            policy_rule=decision.reason,
        )

        await log_event(
            AuditEvent(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                event_type=EventType.POLICY_BLOCK,
                risk_level=RiskLevel.CRITICAL,
                target_url=request.target_url,
                request_summary=_summarize_body(request.body),
                blocked=True,
                policy_rule=decision.reason,
                duration_ms=elapsed,
            )
        )
        return response

    # --- Step 2: Forward request to target ---
    try:
        status_code, resp_headers, resp_body = await forward_request(
            target_url=request.target_url,
            method=request.method,
            headers=request.headers,
            body=request.body,
        )
    except Exception as e:
        logger.error("Forward failed for %s: %s", request.target_url, e, exc_info=True)
        elapsed = int((time.time() - start) * 1000)
        response = ProxyResponse(
            status_code=502,
            body={"error": "Target unreachable", "detail": str(e)},
            risk_level=RiskLevel.LOW,
        )
        await log_event(
            AuditEvent(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                event_type=EventType.REQUEST,
                risk_level=RiskLevel.LOW,
                target_url=request.target_url,
                request_summary=_summarize_body(request.body),
                response_summary=f"Error: {e}",
                blocked=False,
                duration_ms=elapsed,
            )
        )
        return response

    # --- Step 3: Truncate response if too large ---
    max_size = policy.max_response_size_kb * 1024
    scan_body = resp_body[:max_size] if len(resp_body) > max_size else resp_body

    # --- Step 4: Scan response for injection ---
    detection = await analyze_content(
        content=scan_body,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
    )

    elapsed = int((time.time() - start) * 1000)

    if detection.is_threat and detection.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        response = ProxyResponse(
            status_code=200,
            headers=resp_headers,
            body={
                "warning": "ClawGuard blocked this response — prompt injection detected",
                "risk_level": detection.risk_level.value,
                "patterns": detection.matched_patterns,
            },
            blocked=True,
            risk_level=detection.risk_level,
            threats_detected=detection.matched_patterns,
        )

        await log_event(
            AuditEvent(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                event_type=EventType.INJECTION_BLOCKED,
                risk_level=detection.risk_level,
                target_url=request.target_url,
                request_summary=_summarize_body(request.body),
                response_summary=scan_body[:500],
                blocked=True,
                detection_details={
                    "patterns": detection.matched_patterns,
                    "confidence": detection.confidence,
                    "llm_explanation": detection.llm_explanation,
                    "scan_duration_ms": detection.scan_duration_ms,
                },
                duration_ms=elapsed,
            )
        )
        return response

    # --- Step 5: Clean response, pass through ---
    event_type = EventType.INJECTION_DETECTED if detection.is_threat else EventType.RESPONSE
    response = ProxyResponse(
        status_code=status_code,
        headers=resp_headers,
        body=resp_body,
        blocked=False,
        risk_level=detection.risk_level,
        threats_detected=detection.matched_patterns if detection.is_threat else [],
    )

    await log_event(
        AuditEvent(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            event_type=event_type,
            risk_level=detection.risk_level,
            target_url=request.target_url,
            request_summary=_summarize_body(request.body),
            response_summary=scan_body[:300],
            blocked=False,
            detection_details={
                "patterns": detection.matched_patterns,
                "confidence": detection.confidence,
                "scan_duration_ms": detection.scan_duration_ms,
            }
            if detection.is_threat
            else None,
            duration_ms=elapsed,
        )
    )
    return response


def _summarize_body(body: dict | str | None) -> str:
    if body is None:
        return ""
    s = str(body)
    return s[:300] if len(s) > 300 else s
