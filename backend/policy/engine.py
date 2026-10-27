from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

from policy.models import Policy
from policy.urls import origin, parse_target


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    addresses: tuple[str, ...] = ()


async def _resolve_host(hostname: str) -> tuple[str, ...]:
    try:
        return (str(ipaddress.ip_address(hostname)),)
    except ValueError:
        pass
    try:
        async with asyncio.timeout(5):
            infos = await asyncio.get_running_loop().getaddrinfo(
                hostname, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
            )
        return tuple(dict.fromkeys(str(info[4][0]) for info in infos))
    except (OSError, TimeoutError):
        return ()


def is_public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        # Translation and tunnel prefixes can embed a forbidden IPv4 address.
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if any(address in ipaddress.ip_network(prefix) for prefix in ('64:ff9b::/96', '64:ff9b:1::/48')):
            return False
    return True


async def _check_network_rules(target_url: str, policy: Policy) -> PolicyDecision:
    try:
        url = parse_target(target_url)
        hostname = url.raw_host.decode('ascii')
        addresses = await _resolve_host(hostname)
        if not addresses:
            return PolicyDecision(False, 'Destination DNS resolution failed')
        for value in addresses:
            if not is_public_address(value):
                return PolicyDecision(False, 'Non-public destination blocked')
            address = ipaddress.ip_address(value)
            for rule in policy.network_rules:
                if hostname == rule.pattern:
                    return PolicyDecision(False, rule.reason)
                try:
                    network = ipaddress.ip_network(rule.pattern, strict=False)
                except ValueError:
                    continue
                if address in network:
                    return PolicyDecision(False, rule.reason)
        return PolicyDecision(True, 'Destination approved', addresses)
    except ValueError:
        return PolicyDecision(False, 'Invalid destination URL or address')


def _check_tool_permissions(agent_id: str, tool_name: str, policy: Policy) -> PolicyDecision | None:
    permissions = policy.agent_rules.get(agent_id, [])
    matches = [perm for perm in permissions if tool_name == perm.tool_name]
    if not matches or any(not perm.allowed for perm in matches):
        return PolicyDecision(False, f"Tool not permitted for agent '{agent_id}'")
    return None


async def evaluate_request(
    target_url: str, agent_id: str, tool_name: str, policy: Policy, method: str = 'GET',
) -> PolicyDecision:
    tool_result = _check_tool_permissions(agent_id, tool_name, policy)
    if tool_result:
        return tool_result
    if method not in policy.allowed_methods.get(agent_id, ['GET', 'HEAD']):
        return PolicyDecision(False, 'HTTP method not permitted')
    try:
        url = parse_target(target_url)
    except ValueError:
        return PolicyDecision(False, 'Invalid destination URL')
    if origin(url) not in policy.allowed_origins.get(agent_id, []):
        return PolicyDecision(False, 'Destination origin not approved for this agent')
    return await _check_network_rules(str(url), policy)
