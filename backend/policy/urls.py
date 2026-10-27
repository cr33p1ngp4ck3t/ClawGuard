"""Use the same URL parser for policy decisions and outbound requests."""
import re

import httpx


def parse_target(value: str) -> httpx.URL:
    if re.search(r"[\x00-\x20\x7f\\]|%0[ad]|%00", value, re.IGNORECASE):
        raise ValueError("Invalid URL characters")
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL as exc:
        raise ValueError("Invalid URL") from exc
    if (
        url.scheme != "https" or not url.host or url.userinfo or url.fragment
        or url.host.endswith(".") or "%" in url.host
    ):
        raise ValueError("An absolute HTTPS URL without credentials or fragment is required")
    return url


def origin(url: httpx.URL) -> str:
    return str(url.copy_with(path="", query=None, fragment=None))
