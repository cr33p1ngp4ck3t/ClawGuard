from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

from policy.models import Policy


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


def _resolve_host(hostname: str) -> str | None:
    """Resolve hostname to IP. Returns None if resolution fails."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _check_network_rules(target_url: str, policy: Policy) -> PolicyDecision | None:
    """Check if target URL is denied by network rules."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    # Try to parse as IP directly
    target_ip = None
    try:
        target_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # It's a hostname, resolve it
        resolved = _resolve_host(hostname)
        if resolved:
            try:
                target_ip = ipaddress.ip_address(resolved)
            except ValueError:
                pass

    for rule in policy.network_rules:
        if rule.action != "deny":
            continue

        # Check exact hostname/IP match
        if hostname == rule.pattern:
            return PolicyDecision(allowed=False, reason=rule.reason)

        # Check CIDR match
        if target_ip:
            try:
                network = ipaddress.ip_network(rule.pattern, strict=False)
                if target_ip in network:
                    return PolicyDecision(allowed=False, reason=rule.reason)
            except ValueError:
                pass

    return None


def _check_tool_permissions(
    agent_id: str, tool_name: str, policy: Policy
) -> PolicyDecision | None:
    """Check if agent is allowed to use this tool."""
    perms = policy.agent_rules.get(agent_id)

    if perms is None:
        # No rules for this agent — deny by default
        return PolicyDecision(
            allowed=False,
            reason=f"No policy rules defined for agent '{agent_id}' — denied by default",
        )

    for perm in perms:
        if fnmatch.fnmatch(tool_name, perm.tool_name):
            if not perm.allowed:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Agent '{agent_id}' denied access to tool '{tool_name}' by policy",
                )
            return None  # Explicitly allowed

    # No matching rule found — deny by default
    return PolicyDecision(
        allowed=False,
        reason=f"No matching policy rule for agent '{agent_id}' using tool '{tool_name}' — denied by default",
    )


def evaluate_request(
    target_url: str,
    agent_id: str,
    tool_name: str,
    policy: Policy,
) -> PolicyDecision:
    """Evaluate a proxy request against the policy. Returns allow/deny decision."""
    # Check network rules first (SSRF prevention)
    network_result = _check_network_rules(target_url, policy)
    if network_result is not None:
        return network_result

    # Check tool permissions
    tool_result = _check_tool_permissions(agent_id, tool_name, policy)
    if tool_result is not None:
        return tool_result

    return PolicyDecision(allowed=True, reason="Request allowed by policy")
