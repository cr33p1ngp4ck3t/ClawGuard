import json
from unittest.mock import AsyncMock, patch

import pytest

from audit.db import query_events
from audit.models import ProxyRequest
from proxy.handler import handle_proxy_request


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [RuntimeError("secret token"), ValueError("secret token")])
async def test_scanner_failure_blocks_content(test_policy, test_db, failure):
    with patch("proxy.handler.forward_request", AsyncMock(return_value=(200, {}, "private research"))), patch(
        "proxy.handler.analyze_content", AsyncMock(side_effect=failure),
    ):
        response = await handle_proxy_request(ProxyRequest(
            target_url="https://api.example.com/data", agent_id="test-agent", tool_name="web_search",
        ), test_policy)
    assert response.blocked
    assert response.status_code == 503
    assert "secret token" not in response.model_dump_json()


@pytest.mark.asyncio
async def test_audit_redacts_sensitive_request_and_response(test_policy, test_db):
    with patch("proxy.handler.forward_request", AsyncMock(return_value=(200, {}, "private response"))):
        response = await handle_proxy_request(ProxyRequest(
            target_url="https://api.example.com/secret-path?key=query-secret", agent_id="test-agent",
            tool_name="web_search", headers={"Authorization": "Bearer upstream-secret"},
        ), test_policy)
    assert not response.blocked
    events = await query_events()
    serialized = json.dumps(events)
    for secret in ("secret-path", "query-secret", "upstream-secret", "private response"):
        assert secret not in serialized
    assert any(event["target_url"] == "https://api.example.com" for event in events)


@pytest.mark.asyncio
async def test_large_envelope_is_rejected_before_parsing(client):
    response = await client.post("/proxy", content=b"x" * (1024 * 1024 + 1))
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_audit_write_failure_withholds_successful_response(client):
    with patch("proxy.handler.forward_request", AsyncMock(return_value=(200, {}, "private result"))), patch(
        "audit.logger.insert_event", AsyncMock(side_effect=OSError("disk full")),
    ):
        response = await client.post("/proxy", json={
            "target_url": "https://api.example.com/data", "tool_name": "web_search",
        })
    assert response.status_code == 503
    assert "private result" not in response.text
