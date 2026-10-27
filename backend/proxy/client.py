from __future__ import annotations

import asyncio
import re

import httpx

from policy.engine import is_public_address
from policy.urls import parse_target

_FORBIDDEN_HEADERS = {
    'host', 'connection', 'content-length', 'transfer-encoding', 'te', 'trailer',
    'upgrade', 'proxy-authorization', 'proxy-authenticate', 'accept-encoding', 'keep-alive',
}


class ForwardBlocked(ValueError):
    """A bounded, client-safe explanation of an outbound rejection."""


def validate_headers(headers: dict[str, str]) -> None:
    if len(headers) > 32 or sum(len(k) + len(v) for k, v in headers.items()) > 8192:
        raise ForwardBlocked('Request headers too large')
    for name, value in headers.items():
        if name.lower() in _FORBIDDEN_HEADERS or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ForwardBlocked('Request header not permitted')
        if any(ord(char) < 32 or ord(char) > 126 for char in value):
            raise ForwardBlocked('Invalid request header value')


async def forward_request(
    target_url: str,
    method: str = 'GET',
    headers: dict[str, str] | None = None,
    body: dict | str | None = None,
    timeout: float = 10.0,
    *,
    addresses: tuple[str, ...],
    max_bytes: int = 512 * 1024,
) -> tuple[int, dict[str, str], str]:
    url = parse_target(target_url)
    if method not in ('GET', 'HEAD', 'POST') or (body is not None and method != 'POST'):
        raise ForwardBlocked('Only POST requests may have a body')
    if not addresses or not all(is_public_address(address) for address in addresses):
        raise ForwardBlocked('A checked public destination is required')
    outbound = dict(headers or {})
    validate_headers(outbound)
    outbound['Host'] = url.netloc.decode('ascii')
    outbound['Accept-Encoding'] = 'identity'
    # Pin the connection; retain the original hostname for certificate verification.
    connect_url = url.copy_with(host=addresses[0])
    async with asyncio.timeout(timeout):
        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as client:
            async with client.stream(
                method, connect_url, headers=outbound,
                json=body if isinstance(body, dict) else None,
                content=body if isinstance(body, str) else None,
                extensions={'sni_hostname': url.raw_host.decode('ascii')},
            ) as response:
                if 300 <= response.status_code < 400:
                    raise ForwardBlocked('Redirects are blocked; approve and request the destination directly')
                if response.headers.get('content-encoding', 'identity').lower() != 'identity':
                    raise ForwardBlocked('Encoded responses are not supported')
                if method == 'HEAD' or response.status_code == 204:
                    return response.status_code, {}, ''
                content_type = response.headers.get('content-type', '').split(';')[0].strip().lower()
                if not re.fullmatch(r'(text/[a-z0-9.+-]+|application/(json|xml|[a-z0-9.-]+\+json))', content_type):
                    raise ForwardBlocked('Response must declare a supported text content type')
                data = bytearray()
                async for chunk in response.aiter_raw():
                    if len(data) + len(chunk) > max_bytes:
                        raise ForwardBlocked('Response exceeded the configured byte limit')
                    data.extend(chunk)
                try:
                    text = data.decode('utf-8', errors='strict')
                except UnicodeError as exc:
                    raise ForwardBlocked('Response must contain UTF-8 text') from exc
                return response.status_code, {'content-type': content_type}, text
