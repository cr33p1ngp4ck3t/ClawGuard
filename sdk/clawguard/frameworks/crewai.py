"""CrewAI integration for ClawGuard."""
from __future__ import annotations

import httpx

from clawguard.exceptions import RequestBlockedError


def clawguard_tool(
    target_url: str,
    tool_name: str,
    agent_id: str = "crewai-agent",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | str | None = None,
    base_url: str = "http://localhost:8000",
) -> str:
    """Generic ClawGuard wrapper for CrewAI tool calls.

    Usage:
        from crewai import Agent, Task
        from clawguard.frameworks.crewai import clawguard_tool

        result = clawguard_tool(
            target_url="https://api.example.com/data",
            tool_name="web_search",
            agent_id="research-agent",
        )
    """
    with httpx.Client(timeout=10.0) as client:
        resp = client.post(
            f"{base_url}/proxy",
            json={
                "target_url": target_url,
                "method": method,
                "headers": headers or {},
                "body": body,
                "agent_id": agent_id,
                "tool_name": tool_name,
            },
        )
        data = resp.json()

    if data.get("blocked"):
        raise RequestBlockedError(
            threats=data.get("threats_detected", []),
            risk_level=data.get("risk_level", "unknown"),
            policy_rule=data.get("policy_rule"),
        )

    return str(data.get("body", ""))
