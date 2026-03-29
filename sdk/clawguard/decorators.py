"""ClawGuard decorator for protecting function outputs."""
from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable

from clawguard.client import ClawGuardClient
from clawguard.exceptions import RequestBlockedError


def protect(
    base_url: str = "http://localhost:8000",
    agent_id: str = "sdk-agent",
    tool_name: str | None = None,
    raise_on_threat: bool = True,
) -> Callable:
    """Decorator that scans a function's return value through ClawGuard.

    Wraps both sync and async functions. The function's return value is sent
    to ClawGuard's /api/scan endpoint for injection detection.

    Args:
        base_url: ClawGuard server URL.
        agent_id: Agent identifier for policy/audit.
        tool_name: Tool name (defaults to function name).
        raise_on_threat: If True, raises RequestBlockedError on detection.

    Usage:
        @protect(agent_id="my-agent")
        async def fetch_data(url: str) -> str:
            return httpx.get(url).text
    """

    def decorator(func: Callable) -> Callable:
        resolved_tool = tool_name or func.__name__

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = await func(*args, **kwargs)
            return await _scan_result(result, base_url, agent_id, resolved_tool, raise_on_threat)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            result = func(*args, **kwargs)
            return asyncio.get_event_loop().run_until_complete(
                _scan_result(result, base_url, agent_id, resolved_tool, raise_on_threat)
            )

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


async def _scan_result(
    result: Any,
    base_url: str,
    agent_id: str,
    tool_name: str,
    raise_on_threat: bool,
) -> Any:
    """Scan a result through ClawGuard. Returns the result if clean."""
    content = str(result)
    if not content:
        return result

    client = ClawGuardClient(base_url=base_url, agent_id=agent_id)
    scan = await client.scan(content=content, tool_name=tool_name)

    if scan.is_threat and raise_on_threat:
        raise RequestBlockedError(
            threats=scan.matched_patterns,
            risk_level=scan.risk_level,
        )
    return result
