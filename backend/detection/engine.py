from __future__ import annotations

import time

from audit.models import DetectionResult, RiskLevel
from detection.patterns import (
    RISK_THRESHOLD_CRITICAL,
    RISK_THRESHOLD_HIGH,
    RISK_THRESHOLD_MEDIUM,
)
from detection.regex_detector import scan_for_injections_weighted


def _score_to_risk(score: float) -> RiskLevel:
    if score >= RISK_THRESHOLD_CRITICAL:
        return RiskLevel.CRITICAL
    if score >= RISK_THRESHOLD_HIGH:
        return RiskLevel.HIGH
    if score >= RISK_THRESHOLD_MEDIUM:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


async def analyze_content(
    content: str, agent_id: str = "", tool_name: str = ""
) -> DetectionResult:
    """Run all detectors on content. Returns aggregate DetectionResult with weighted scoring."""
    start = time.time()

    matches, cumulative_score = scan_for_injections_weighted(content)

    if not matches:
        elapsed = int((time.time() - start) * 1000)
        return DetectionResult(
            is_threat=False,
            risk_level=RiskLevel.LOW,
            matched_patterns=[],
            confidence=1.0,
            scan_duration_ms=elapsed,
        )

    pattern_names = list({m.pattern_name for m in matches})
    risk_level = _score_to_risk(cumulative_score)
    is_threat = risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    # LLM enhancement: run on medium-risk matches for semantic confirmation
    llm_explanation = None
    if risk_level == RiskLevel.MEDIUM and _should_call_llm(content):
        try:
            from detection.llm_detector import classify_injection

            result = await classify_injection(content)
            if result:
                llm_explanation = result.get("explanation")
                if result.get("is_injection") and result.get("confidence", 0) > 0.7:
                    risk_level = RiskLevel.HIGH
                    is_threat = True
                    cumulative_score = max(cumulative_score, 0.8)
        except Exception:
            pass  # LLM is optional, never block on its failure

    confidence = min(cumulative_score, 1.0)

    elapsed = int((time.time() - start) * 1000)

    return DetectionResult(
        is_threat=is_threat,
        risk_level=risk_level,
        matched_patterns=pattern_names,
        llm_explanation=llm_explanation,
        confidence=round(confidence, 2),
        scan_duration_ms=elapsed,
    )


def _should_call_llm(text: str) -> bool:
    """Cheap heuristic gate: only call LLM if content looks suspicious and is small enough."""
    triggers = ["ignore", "system", "instruction", "base64", "execute", "override"]
    return any(t in text.lower() for t in triggers) and len(text) < 5000
