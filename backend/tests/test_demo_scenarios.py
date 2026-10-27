"""Retain attack scenarios as tests without shipping a public demo trigger."""
import pytest

from demo.scenarios import SCENARIOS


@pytest.mark.asyncio
async def test_demo_trigger_is_not_deployed(client):
    assert (await client.post('/api/demo/run')).status_code == 404


@pytest.mark.asyncio
async def test_original_ssrf_and_tool_attacks_remain_blocked(client):
    for scenario in SCENARIOS[1:]:
        request = {**scenario['request'], 'agent_id': 'test-agent'}
        response = await client.post('/proxy', json=request)
        assert response.status_code == 200
        assert response.json()['blocked']
