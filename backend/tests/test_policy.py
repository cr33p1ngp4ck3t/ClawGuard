"""Tests for policy evaluation and loader."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from policy.engine import PolicyDecision, _check_tool_permissions, evaluate_request
from policy.loader import PolicyLoadError, load_policy
from policy.models import NetworkRule, Policy, ToolPermission


@pytest.fixture
def policy():
    return load_policy(str(Path(__file__).parent / "fixtures" / "test_policy.yaml"))


# --- Tool permissions ---

class TestToolPermissions:
    def test_allowed_tool(self, policy):
        result = _check_tool_permissions("test-agent", "web_search", policy)
        assert result is None  # None = allowed

    def test_denied_tool_glob(self, policy):
        result = _check_tool_permissions("test-agent", "shell.execute", policy)
        assert result is not None
        assert not result.allowed

    def test_denied_tool_explicit(self, policy):
        result = _check_tool_permissions("test-agent", "file.write", policy)
        assert result is not None
        assert not result.allowed

    def test_unknown_agent_denied(self, policy):
        result = _check_tool_permissions("unknown-agent", "web_search", policy)
        assert result is not None
        assert not result.allowed
        assert "unknown-agent" in result.reason

    def test_no_matching_rule_denied(self, policy):
        result = _check_tool_permissions("test-agent", "database.query", policy)
        assert result is not None
        assert not result.allowed

    def test_wildcard_agent_allows_all(self, policy):
        result = _check_tool_permissions("wildcard-agent", "anything.here", policy)
        assert result is None


# --- Network rules ---

class TestNetworkRules:
    @pytest.mark.asyncio
    async def test_ssrf_internal_blocked(self, policy):
        from policy.engine import _check_network_rules
        result = await _check_network_rules("http://10.0.0.1/secret", policy)
        assert result is not None
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_metadata_blocked(self, policy):
        from policy.engine import _check_network_rules
        result = await _check_network_rules("http://169.254.169.254/latest/meta-data/", policy)
        assert result is not None
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_public_url_allowed(self, policy):
        from policy.engine import _check_network_rules
        result = await _check_network_rules("https://api.example.com/data", policy)
        assert result is None


# --- Full evaluate_request ---

class TestEvaluateRequest:
    @pytest.mark.asyncio
    async def test_allowed_request(self, policy):
        result = await evaluate_request(
            target_url="https://api.example.com/search",
            agent_id="test-agent",
            tool_name="web_search",
            policy=policy,
        )
        assert result.allowed

    @pytest.mark.asyncio
    async def test_ssrf_blocked(self, policy):
        result = await evaluate_request(
            target_url="http://169.254.169.254/latest/meta-data/",
            agent_id="test-agent",
            tool_name="web_search",
            policy=policy,
        )
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_unauthorized_tool_blocked(self, policy):
        result = await evaluate_request(
            target_url="https://api.example.com/run",
            agent_id="test-agent",
            tool_name="shell.execute",
            policy=policy,
        )
        assert not result.allowed


# --- Loader ---

class TestPolicyLoader:
    def test_valid_policy(self, policy):
        assert policy.name == "Test Policy"
        assert len(policy.agent_rules) == 2
        assert len(policy.network_rules) == 2

    def test_missing_file(self):
        with pytest.raises(PolicyLoadError, match="not found"):
            load_policy("/nonexistent/path/policy.yaml")

    def test_malformed_yaml(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("name: [\ninvalid: {{\n  broken")
        with pytest.raises(PolicyLoadError, match="Invalid YAML"):
            load_policy(str(bad))

    def test_missing_name(self, tmp_path):
        no_name = tmp_path / "noname.yaml"
        no_name.write_text("version: '1.0'\nagent_rules: {}\n")
        with pytest.raises(PolicyLoadError, match="'name'"):
            load_policy(str(no_name))

    def test_non_dict_yaml(self, tmp_path):
        bad = tmp_path / "list.yaml"
        bad.write_text("- item1\n- item2\n")
        with pytest.raises(PolicyLoadError, match="mapping"):
            load_policy(str(bad))
