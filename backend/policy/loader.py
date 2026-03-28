from __future__ import annotations

from pathlib import Path

import yaml

from policy.models import NetworkRule, Policy, ToolPermission


def load_policy(path: str) -> Policy:
    """Load and parse a YAML policy file into a Policy model."""
    raw = yaml.safe_load(Path(path).read_text())

    agent_rules: dict[str, list[ToolPermission]] = {}
    for agent_id, perms in raw.get("agent_rules", {}).items():
        agent_rules[agent_id] = [
            ToolPermission(**p) for p in perms
        ]

    network_rules = [
        NetworkRule(**r) for r in raw.get("network_rules", [])
    ]

    return Policy(
        name=raw.get("name", "unnamed"),
        version=raw.get("version", "1.0"),
        agent_rules=agent_rules,
        network_rules=network_rules,
        max_response_size_kb=raw.get("max_response_size_kb", 1024),
    )
