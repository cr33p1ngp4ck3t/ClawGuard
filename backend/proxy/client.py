from __future__ import annotations

import httpx


async def forward_request(
    target_url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict | str | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], str]:
    """Forward a request to the target URL. Returns (status_code, headers, body_text)."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        request_kwargs: dict = {
            "method": method.upper(),
            "url": target_url,
            "headers": headers or {},
        }

        if body is not None and method.upper() in ("POST", "PUT", "PATCH"):
            if isinstance(body, dict):
                request_kwargs["json"] = body
            else:
                request_kwargs["content"] = body

        response = await client.request(**request_kwargs)

        resp_headers = dict(response.headers)
        return response.status_code, resp_headers, response.text
