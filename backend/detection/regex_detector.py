from __future__ import annotations

import re
import unicodedata

from audit.models import PatternMatch, RiskLevel
from detection.patterns import INJECTION_PATTERNS

# Zero-width and invisible Unicode characters
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff]")


def normalize_text(text: str) -> str:
    """Normalize text to defeat evasion: strip zero-width chars, NFKC normalize."""
    text = _ZERO_WIDTH_RE.sub("", text)
    return unicodedata.normalize("NFKC", text)


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
    """Scan text and return matches + cumulative risk score (0.0-1.0+).

    Runs patterns against both original and normalized text to catch
    zero-width character and encoding evasion attempts.
    """
    matches: list[PatternMatch] = []
    seen_patterns: set[str] = set()
    cumulative_score = 0.0

    normalized = normalize_text(text)
    # Scan both original (catches UNICODE_EVASION) and normalized (catches hidden injections)
    targets = [text] if text == normalized else [text, normalized]

    for target in targets:
        for pattern_def in INJECTION_PATTERNS:
            for match in pattern_def["pattern"].finditer(target):
                matches.append(
                    PatternMatch(
                        pattern_name=pattern_def["name"],
                        matched_text=match.group()[:200],
                        severity=pattern_def["severity"],
                        position=match.start(),
                    )
                )
                # Count each pattern type once for scoring
                if pattern_def["name"] not in seen_patterns:
                    cumulative_score += pattern_def["weight"]
                    seen_patterns.add(pattern_def["name"])

    return matches, round(cumulative_score, 2)
