import logging
import os
import sys


GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
DB_PATH: str = os.getenv("DB_PATH", "clawguard.db")
PROXY_PORT: int = int(os.getenv("PROXY_PORT", "8000"))
CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
POLICY_PATH: str = os.getenv("POLICY_PATH", "policies/default.yaml")
LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "3"))
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")


def setup_logging() -> None:
    """Configure structured logging for ClawGuard."""
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)-25s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
    # Quiet noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
