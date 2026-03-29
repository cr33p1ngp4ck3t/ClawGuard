"""ClawGuard SDK exceptions."""
from __future__ import annotations


class ClawGuardError(Exception):
    """Base exception for ClawGuard SDK errors."""


class RequestBlockedError(ClawGuardError):
    """Raised when ClawGuard blocks a request due to a security threat."""

    def __init__(self, threats: list[str], risk_level: str, policy_rule: str | None = None):
        self.threats = threats
        self.risk_level = risk_level
        self.policy_rule = policy_rule
        detail = ", ".join(threats) if threats else policy_rule or "blocked by policy"
        super().__init__(f"Request blocked by ClawGuard ({risk_level}): {detail}")
