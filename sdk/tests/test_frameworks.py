"""Framework helpers share the authenticated SDK request boundary."""
import json

import pytest
import respx

from clawguard.exceptions import ClawGuardError, RequestBlockedError
from clawguard.frameworks.crewai import clawguard_tool
from clawguard.frameworks.langchain import clawguard_tool_wrapper


@respx.mock
def test_crewai_preserves_upstream_headers_and_authenticates_gateway():
    route = respx.post("http://localhost:8000/proxy").respond(200, json={
        "status_code": 200, "body": "data", "blocked": False,
    })
    assert clawguard_tool(
        "https://api.example.com/data", "research", api_key="agent-key",
        headers={"Authorization": "Bearer upstream-key"},
    ) == "data"
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer agent-key"
    assert json.loads(request.content)["headers"]["Authorization"] == "Bearer upstream-key"


@respx.mock
def test_crewai_reports_policy_block():
    respx.post("http://localhost:8000/proxy").respond(200, json={
        "status_code": 403, "blocked": True, "policy_rule": "domain_allowlist",
    })
    with pytest.raises(RequestBlockedError, match="domain_allowlist"):
        clawguard_tool("https://unapproved.example/data", "research", api_key="agent-key")


@respx.mock
def test_langchain_uses_explicit_url_and_environment_key(monkeypatch):
    monkeypatch.setenv("CLAWGUARD_API_KEY", "agent-key")
    route = respx.post("http://localhost:8000/proxy").respond(200, json={
        "status_code": 200, "body": "page", "blocked": False,
    })
    guarded = clawguard_tool_wrapper(lambda url: url, tool_name="fetch_page")
    assert guarded(url="https://api.example.com/data") == "page"
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer agent-key"
    assert json.loads(request.content)["target_url"] == "https://api.example.com/data"


def test_langchain_requires_a_url_instead_of_inventing_a_search_api():
    guarded = clawguard_tool_wrapper(lambda query: query, tool_name="research")
    with pytest.raises(ClawGuardError, match="URL"):
        guarded("research topic")
