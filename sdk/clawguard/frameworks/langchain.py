"""LangChain integration for ClawGuard."""
from __future__ import annotations

from typing import Any, Callable

from clawguard.client import ClawGuardClient
from clawguard.exceptions import ClawGuardError


def clawguard_tool_wrapper(
    func: Callable,
    tool_name: str,
    base_url: str = "http://localhost:8000",
    agent_id: str = "langchain-agent",
    api_key: str | None = None,
) -> Callable:
    """Wrap a URL-fetching LangChain tool to route GET calls through ClawGuard.

    The wrapper sends the tool's target URL through the ClawGuard proxy
    instead of calling it directly. It replaces the function with a guarded
    GET request; api_key defaults to CLAWGUARD_API_KEY.

    Usage:
        from langchain.tools import Tool
        from clawguard.frameworks.langchain import clawguard_tool_wrapper

        def fetch_page(url: str) -> str:
            return httpx.get(url).text

        guarded_fetch = clawguard_tool_wrapper(
            fetch_page, tool_name="fetch_page", agent_id="research-agent"
        )

        fetch_tool = Tool(
            name="fetch_page",
            func=guarded_fetch,
            description="Fetch an approved URL through ClawGuard",
        )
    """

    def wrapper(*args: Any, **kwargs: Any) -> str:
        target_url = args[0] if args else kwargs.get("url", kwargs.get("query", ""))
        if not isinstance(target_url, str) or not target_url.startswith(("https://", "http://")):
            raise ClawGuardError("The guarded URL-fetch tool requires an explicit HTTP(S) URL")
        client = ClawGuardClient(base_url=base_url, agent_id=agent_id, api_key=api_key)
        result = client.check_sync(target_url, tool_name=tool_name)
        if result.blocked:
            reason = ", ".join(result.threats_detected) or result.policy_rule or "blocked by policy"
            return f"[ClawGuard] Request blocked: {reason}"
        return str(result.body)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
