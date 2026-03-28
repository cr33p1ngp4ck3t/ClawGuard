import os


GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
DB_PATH: str = os.getenv("DB_PATH", "clawguard.db")
PROXY_PORT: int = int(os.getenv("PROXY_PORT", "8000"))
CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
POLICY_PATH: str = os.getenv("POLICY_PATH", "policies/default.yaml")
LLM_TIMEOUT: int = int(os.getenv("LLM_TIMEOUT", "3"))
LLM_MODEL: str = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
