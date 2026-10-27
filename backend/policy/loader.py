from __future__ import annotations

import logging
from pathlib import Path

import yaml

from policy.models import Policy

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
        policy = Policy.model_validate(raw)
    except (TypeError, ValueError) as e:
        raise PolicyLoadError(f"Invalid policy structure in {policy_path}: {e}")

    logger.info("Loaded policy '%s' v%s (%d agents, %d network rules)",
                policy.name, policy.version, len(policy.agent_rules), len(policy.network_rules))
    return policy
