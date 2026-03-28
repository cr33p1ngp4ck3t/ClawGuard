from __future__ import annotations

from audit.models import PatternMatch, RiskLevel
from detection.patterns import INJECTION_PATTERNS


def scan_for_injections(text: str) -> list[PatternMatch]:
    """Scan text for prompt injection patterns. Returns all matches found."""
    matches: list[PatternMatch] = []

    for pattern_def in INJECTION_PATTERNS:
        for match in pattern_def["pattern"].finditer(text):
            matches.append(
                PatternMatch(
                    pattern_name=pattern_def["name"],
                    matched_text=match.group()[:200],
                    severity=pattern_def["severity"],
                    position=match.start(),
                )
            )

    return matches


def scan_for_injections_weighted(text: str) -> tuple[list[PatternMatch], float]:
    """Scan text and return matches + cumulative risk score (0.0-1.0+)."""
    matches: list[PatternMatch] = []
    seen_patterns: set[str] = set()
    cumulative_score = 0.0

    for pattern_def in INJECTION_PATTERNS:
        for match in pattern_def["pattern"].finditer(text):
            matches.append(
                PatternMatch(
                    pattern_name=pattern_def["name"],
                    matched_text=match.group()[:200],
                    severity=pattern_def["severity"],
                    position=match.start(),
                )
            )
            # Count each pattern type once for scoring (avoid inflating from repeated matches)
            if pattern_def["name"] not in seen_patterns:
                cumulative_score += pattern_def["weight"]
                seen_patterns.add(pattern_def["name"])

    return matches, round(cumulative_score, 2)
