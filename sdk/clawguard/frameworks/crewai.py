"""CrewAI integration for ClawGuard."""
from __future__ import annotations

from clawguard.client import ClawGuardClient


def clawguard_tool(
    target_url: str,
    tool_name: str,
    agent_id: str = "crewai-agent",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | str | None = None,
    base_url: str = "http://localhost:8000",
    api_key: str | None = None,
) -> str:
    """Generic ClawGuard wrapper for CrewAI tool calls.

    api_key defaults to CLAWGUARD_API_KEY; agent_id must match its identity.

    Usage:
        from crewai import Agent, Task
        from clawguard.frameworks.crewai import clawguard_tool

        result = clawguard_tool(
            target_url="https://api.example.com/data",
            tool_name="web_search",
            agent_id="research-agent",
        )
    """
    client = ClawGuardClient(base_url=base_url, agent_id=agent_id, api_key=api_key)
    result = client.check_sync(
        target_url=target_url, method=method, headers=headers, body=body,
        tool_name=tool_name, raise_on_block=True,
    )
    return str(result.body)
