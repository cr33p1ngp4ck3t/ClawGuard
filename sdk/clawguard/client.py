"""ClawGuard SDK client."""
from __future__ import annotations

import httpx

from clawguard.exceptions import ClawGuardError, RequestBlockedError
from clawguard.types import ProxyResult, ScanResult


class ClawGuardClient:
    """Client for interacting with a ClawGuard server.

    Usage:
        client = ClawGuardClient()  # defaults to localhost:8000
        result = await client.check(
            target_url="https://api.example.com/data",
            agent_id="my-agent",
            tool_name="web_search",
        )
        if result.blocked:
            print(f"Blocked: {result.threats_detected}")
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        agent_id: str = "sdk-agent",
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.timeout = timeout

    async def check(
        self,
        target_url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: dict | str | None = None,
        agent_id: str | None = None,
        tool_name: str = "unknown",
        raise_on_block: bool = False,
    ) -> ProxyResult:
        """Send a request through the ClawGuard proxy.

        Args:
            target_url: The actual URL to call.
            method: HTTP method.
            headers: Headers to forward.
            body: Request body (for POST/PUT/PATCH).
            agent_id: Override the default agent_id.
            tool_name: Tool identifier for policy lookup.
            raise_on_block: If True, raises RequestBlockedError when blocked.

        Returns:
            ProxyResult with status, body, blocked flag, and threat info.
        """
        payload = {
            "target_url": target_url,
            "method": method,
            "headers": headers or {},
            "body": body,
            "agent_id": agent_id or self.agent_id,
            "tool_name": tool_name,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                resp = await http.post(f"{self.base_url}/proxy", json=payload)
                resp.raise_for_status()
                result = ProxyResult(**resp.json())
        except httpx.HTTPError as e:
            raise ClawGuardError(f"Failed to reach ClawGuard: {e}") from e

        if raise_on_block and result.blocked:
            raise RequestBlockedError(
                threats=result.threats_detected,
                risk_level=result.risk_level,
                policy_rule=result.policy_rule,
            )
        return result

    def check_sync(
        self,
        target_url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: dict | str | None = None,
        agent_id: str | None = None,
        tool_name: str = "unknown",
        raise_on_block: bool = False,
    ) -> ProxyResult:
        """Synchronous version of check()."""
        payload = {
            "target_url": target_url,
            "method": method,
            "headers": headers or {},
            "body": body,
            "agent_id": agent_id or self.agent_id,
            "tool_name": tool_name,
        }
        try:
            with httpx.Client(timeout=self.timeout) as http:
                resp = http.post(f"{self.base_url}/proxy", json=payload)
                resp.raise_for_status()
                result = ProxyResult(**resp.json())
        except httpx.HTTPError as e:
            raise ClawGuardError(f"Failed to reach ClawGuard: {e}") from e

        if raise_on_block and result.blocked:
            raise RequestBlockedError(
                threats=result.threats_detected,
                risk_level=result.risk_level,
                policy_rule=result.policy_rule,
            )
        return result

    async def scan(
        self,
        content: str,
        agent_id: str | None = None,
        tool_name: str = "unknown",
    ) -> ScanResult:
        """Scan content for injection without forwarding (uses /api/scan)."""
        payload = {
            "content": content,
            "agent_id": agent_id or self.agent_id,
            "tool_name": tool_name,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                resp = await http.post(f"{self.base_url}/api/scan", json=payload)
                resp.raise_for_status()
                return ScanResult(**resp.json())
        except httpx.HTTPError as e:
            raise ClawGuardError(f"Failed to reach ClawGuard: {e}") from e

    async def health(self) -> dict:
        """Check ClawGuard server health."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                resp = await http.get(f"{self.base_url}/health")
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ClawGuardError(f"Failed to reach ClawGuard: {e}") from e

    async def stats(self) -> dict:
        """Get aggregate statistics from ClawGuard."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as http:
                resp = await http.get(f"{self.base_url}/api/stats")
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as e:
            raise ClawGuardError(f"Failed to reach ClawGuard: {e}") from e
