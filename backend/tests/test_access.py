"""Credentials authorize the gateway, never an identity chosen in request data."""
import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from starlette.websockets import WebSocketDisconnect

from main import app


@pytest.mark.asyncio
@pytest.mark.parametrize("path,payload", [
    ("/proxy", {"target_url": "http://127.0.0.1", "agent_id": "missing", "tool_name": "fetch"}),
    ("/api/scan", {"content": "weather report"}),
])
async def test_agent_endpoints_require_credentials(path, payload, test_db):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(path, json=payload)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_agent_cannot_substitute_identity(client):
    response = await client.post("/proxy", headers={"Authorization": "Bearer " + "t" * 32}, json={
        "target_url": "https://api.example.com/", "agent_id": "wildcard-agent", "tool_name": "web_search",
    })
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/events", "/api/stats", "/api/policy", "/metrics"])
async def test_agent_cannot_read_admin_data(client, path):
    response = await client.get(path, headers={"Authorization": "Bearer " + "t" * 32})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_admin_can_read_metrics_and_events(client):
    for path in ("/api/events", "/metrics"):
        response = await client.get(path, headers={"Authorization": "Bearer " + "a" * 32})
        assert response.status_code == 200


def test_websocket_rejects_wrong_key():
    with TestClient(app) as client:
        with client.websocket_connect("/api/ws") as socket:
            socket.send_json({"token": "wrong"})
            with pytest.raises(WebSocketDisconnect) as error:
                socket.receive_json()
            assert error.value.code == 1008


def test_websocket_confirms_admin_authentication():
    with TestClient(app) as client:
        with client.websocket_connect("/api/ws") as socket:
            socket.send_json({"token": "a" * 32})
            assert socket.receive_json() == {"type": "authenticated"}


@pytest.mark.parametrize("message", ["not-json", "[]", "null", '{"token":123}'])
def test_websocket_rejects_malformed_auth(message):
    with TestClient(app) as client:
        with client.websocket_connect("/api/ws") as socket:
            socket.send_text(message)
            with pytest.raises(WebSocketDisconnect) as error:
                socket.receive_json()
            assert error.value.code == 1008


@pytest.mark.asyncio
async def test_scan_failure_returns_no_content(client):
    from unittest.mock import AsyncMock, patch
    with patch("api.scan.analyze_content", AsyncMock(side_effect=TimeoutError("sensitive"))):
        response = await client.post("/api/scan", json={"content": "private content"})
    assert response.status_code == 503
    assert "sensitive" not in response.text


@pytest.mark.asyncio
async def test_scan_rejects_unbounded_identifiers(client):
    response = await client.post("/api/scan", json={"content": "text", "tool_name": "x" * 129})
    assert response.status_code == 422
