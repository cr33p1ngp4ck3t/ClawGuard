import json
from unittest.mock import AsyncMock, patch

import pytest

from audit.db import query_events
from audit.models import ProxyRequest
from proxy.handler import handle_proxy_request


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
