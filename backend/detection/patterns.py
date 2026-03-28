from __future__ import annotations

import re

from audit.models import RiskLevel

INJECTION_PATTERNS = [
    {
        "name": "IGNORE_PREVIOUS",
        "pattern": re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|context)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.CRITICAL,
        "weight": 0.9,
        "description": "Attempts to override agent's system prompt",
    },
    {
        "name": "SYSTEM_PROMPT_EXTRACT",
        "pattern": re.compile(
            r"(reveal|show|print|output|display|repeat)\s+(your\s+)?(system\s+prompt|instructions|rules|initial\s+prompt)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.HIGH,
        "weight": 0.7,
        "description": "Attempts to extract agent's system prompt",
    },
    {
        "name": "ROLE_OVERRIDE",
        "pattern": re.compile(
            r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|new\s+role|switch\s+to\s+role|from\s+now\s+on\s+you\s+are)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.HIGH,
        "weight": 0.7,
        "description": "Attempts to change agent's role/persona",
    },
    {
        "name": "HIDDEN_INSTRUCTION",
        "pattern": re.compile(
            r"(\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system|BEGIN\s+HIDDEN|ADMIN\s+OVERRIDE)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.CRITICAL,
        "weight": 0.95,
        "description": "Uses model-specific tokens to inject system-level instructions",
    },
    {
        "name": "BASE64_PAYLOAD",
        "pattern": re.compile(
            r"[A-Za-z0-9+/]{50,}={0,2}",
        ),
        "severity": RiskLevel.MEDIUM,
        "weight": 0.3,
        "description": "Suspicious base64-encoded content that may hide injection",
    },
    {
        "name": "DELIMITER_INJECTION",
        "pattern": re.compile(
            r"(---+\s*END\s*(OF\s+)?(CONTEXT|INPUT|DATA)|={3,}\s*NEW\s*INSTRUCTIONS|###\s*OVERRIDE)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.HIGH,
        "weight": 0.6,
        "description": "Uses delimiters to separate injected instructions from legitimate content",
    },
    {
        "name": "TOOL_CALL_INJECTION",
        "pattern": re.compile(
            r"(call\s+function|execute\s+tool|run\s+command|invoke\s+api).*?(rm\s+-rf|curl|wget|eval|exec|subprocess)",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": RiskLevel.CRITICAL,
        "weight": 0.85,
        "description": "Attempts to manipulate agent into dangerous tool calls",
    },
    {
        "name": "EXFILTRATION_ATTEMPT",
        "pattern": re.compile(
            r"(send|post|transmit|upload|exfiltrate)\s+.{0,50}(to|at)\s+(https?://|ftp://|webhook)",
            re.IGNORECASE,
        ),
        "severity": RiskLevel.HIGH,
        "weight": 0.75,
        "description": "Attempts to exfiltrate data to external URL",
    },
]

# Threshold for blocking based on cumulative weight
RISK_THRESHOLD_CRITICAL = 0.85
RISK_THRESHOLD_HIGH = 0.5
RISK_THRESHOLD_MEDIUM = 0.3
