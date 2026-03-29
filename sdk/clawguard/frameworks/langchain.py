"""LangChain integration for ClawGuard."""
from __future__ import annotations

from typing import Any, Callable

import httpx


def clawguard_tool_wrapper(
    func: Callable,
    tool_name: str,
    base_url: str = "http://localhost:8000",
    agent_id: str = "langchain-agent",
) -> Callable:
    """Wrap a LangChain tool function to route calls through ClawGuard.

    The wrapper sends the tool's target URL through the ClawGuard proxy
    instead of calling it directly.

    Usage:
        from langchain.tools import Tool
        from clawguard.frameworks.langchain import clawguard_tool_wrapper

        def raw_search(query: str) -> str:
            return httpx.get(f"https://api.search.com/search?q={query}").text

        guarded_search = clawguard_tool_wrapper(
            raw_search, tool_name="web_search"
        )

        search_tool = Tool(
            name="web_search",
            func=guarded_search,
            description="Search the web (secured by ClawGuard)",
        )
    """

    def wrapper(*args: Any, **kwargs: Any) -> str:
        # Extract URL from first arg or 'url' kwarg
        query = args[0] if args else kwargs.get("query", "")
        target_url = str(query) if query.startswith("http") else f"https://api.example.com/search?q={query}"

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{base_url}/proxy",
                json={
                    "target_url": target_url,
                    "method": "GET",
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                },
            )
            data = resp.json()

        if data.get("blocked"):
            threats = ", ".join(data.get("threats_detected", []))
            return f"[ClawGuard] Request blocked: {threats}"

        body = data.get("body", "")
        return str(body)

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper
