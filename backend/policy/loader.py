from __future__ import annotations

import logging
from pathlib import Path

import yaml

from policy.models import NetworkRule, Policy, ToolPermission

logger = logging.getLogger("clawguard.policy.loader")


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded or parsed."""


def load_policy(path: str) -> Policy:
    """Load and parse a YAML policy file into a Policy model."""
    policy_path = Path(path)

    # File existence
    try:
        text = policy_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PolicyLoadError(f"Policy file not found: {policy_path.resolve()}")
    except OSError as e:
        raise PolicyLoadError(f"Cannot read policy file {policy_path}: {e}")

    # YAML parsing
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"Invalid YAML in {policy_path}: {e}")

    if not isinstance(raw, dict):
        raise PolicyLoadError(f"Policy file must contain a YAML mapping, got {type(raw).__name__}")

    # Required field validation
    if "name" not in raw:
        raise PolicyLoadError("Policy missing required field: 'name'")

    # Build model
    try:
        agent_rules: dict[str, list[ToolPermission]] = {}
        for agent_id, perms in raw.get("agent_rules", {}).items():
            agent_rules[agent_id] = [ToolPermission(**p) for p in perms]

        network_rules = [NetworkRule(**r) for r in raw.get("network_rules", [])]

        policy = Policy(
            name=raw["name"],
            version=raw.get("version", "1.0"),
            agent_rules=agent_rules,
            network_rules=network_rules,
            max_response_size_kb=raw.get("max_response_size_kb", 1024),
        )
    except (TypeError, ValueError) as e:
        raise PolicyLoadError(f"Invalid policy structure in {policy_path}: {e}")

    logger.info("Loaded policy '%s' v%s (%d agents, %d network rules)",
                policy.name, policy.version, len(agent_rules), len(network_rules))
    return policy
