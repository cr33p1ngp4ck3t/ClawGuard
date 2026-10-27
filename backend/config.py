import logging
import json
import os
import sys
from pathlib import Path


GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
DB_PATH: str = os.getenv("DB_PATH", "clawguard.db")
PROXY_PORT: int = int(os.getenv("PROXY_PORT", "8000"))
CORS_ORIGINS: list[str] = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")]
POLICY_PATH: str = os.getenv("POLICY_PATH", str(Path(__file__).parent / "policies/default.yaml"))
LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "3"))
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
CLAWGUARD_ADMIN_KEY: str = os.getenv("CLAWGUARD_ADMIN_KEY", "")
CLAWGUARD_AGENT_KEYS: dict[str, str] = json.loads(os.getenv("CLAWGUARD_AGENT_KEYS", "{}"))


def validate_credentials(agent_ids: set[str]) -> None:
    keys = CLAWGUARD_AGENT_KEYS
    if not isinstance(keys, dict) or not keys or not set(keys) <= agent_ids:
        raise ValueError("Configure CLAWGUARD_AGENT_KEYS for agents present in the policy")
    values = [CLAWGUARD_ADMIN_KEY, *keys.values()]
    if any(not isinstance(key, str) or len(key) < 32 or not key.isascii() or any(c.isspace() for c in key) for key in values):
        raise ValueError("Admin and agent keys must be distinct ASCII tokens of at least 32 characters")
    if len(set(values)) != len(values):
        raise ValueError("Admin and agent keys must be distinct")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"level": record.levelname, "logger": record.name, "message": record.getMessage()})


def setup_logging() -> None:
    """Configure structured logging for ClawGuard."""
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
