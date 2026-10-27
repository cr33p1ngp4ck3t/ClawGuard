"""The research policy must stop unsafe destinations before transport runs."""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from policy.engine import evaluate_request
from policy.models import Policy, ToolPermission


def research_policy(**kwargs):
    return Policy(
        name="research",
        agent_rules={"research-agent": [ToolPermission(tool_name="web_fetch", allowed=True)]},
        allowed_origins={"research-agent": ["https://example.com"]},
        **kwargs,
    )


def decide(url, addresses=("93.184.216.34",), **kwargs):
    with patch("policy.engine._resolve_host", new=AsyncMock(return_value=addresses)):
        return asyncio.run(evaluate_request(url, "research-agent", "web_fetch", research_policy(), **kwargs))


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/secret", "https://example.com.evil.test/", "https://evil.test/",
    "https://example.com@evil.test/", "https://example.com:8443/", "file:///etc/passwd",
    "https://example.com\\@evil.test/", "https://example.com/#fragment",
    "https://example.com/%0d%0aHeader:evil", "https://example.com./",
])
def test_unapproved_or_ambiguous_destination_is_denied(url):
    assert not decide(url).allowed


@pytest.mark.parametrize("addresses", [
    ("127.0.0.1",), ("10.0.0.1",), ("169.254.169.254",), ("0.0.0.0",),
    ("::1",), ("fc00::1",), ("fe80::1",), ("::ffff:127.0.0.1",),
    ("64:ff9b::7f00:1",), ("2002:7f00:1::",), ("93.184.216.34", "10.0.0.1"), (),
])
def test_every_dns_answer_must_be_public(addresses):
    assert not decide("https://example.com/data", addresses).allowed


def test_clean_url_retains_validated_addresses():
    result = decide("https://example.com/data?q=weather")
    assert result.allowed
    assert result.addresses == ("93.184.216.34",)


def test_international_hostname_resolves_the_approved_ascii_name():
    async def resolve(hostname):
        assert hostname == "xn--fa-hia.de"
        return ("93.184.216.34",)
    policy = research_policy()
    policy.allowed_origins["research-agent"] = ["https://xn--fa-hia.de"]
    with patch("policy.engine._resolve_host", new=resolve):
        result = asyncio.run(evaluate_request("https://xn--fa-hia.de/", "research-agent", "web_fetch", policy))
    assert result.allowed


def test_write_method_requires_explicit_policy():
    assert not decide("https://example.com/data", method="POST").allowed


def test_missing_allowlist_denies_by_default():
    policy = Policy(name="empty", agent_rules={"research-agent": [ToolPermission(tool_name="web_fetch", allowed=True)]})
    result = asyncio.run(evaluate_request("https://example.com/", "research-agent", "web_fetch", policy))
    assert not result.allowed


def test_policy_typo_or_unsupported_condition_fails_validation():
    with pytest.raises(ValueError):
        research_policy(allowed_origin=["https://example.com"])
    with pytest.raises(ValueError):
        ToolPermission(tool_name="web_fetch", allowed=True, conditions={"path_prefix": "/safe/"})
    with pytest.raises(ValueError):
        ToolPermission(tool_name="web_*", allowed=True)
