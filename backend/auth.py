import secrets

from fastapi import Header, HTTPException

import config


def valid_admin(token: str) -> bool:
    return bool(config.CLAWGUARD_ADMIN_KEY) and secrets.compare_digest(
        token.encode(), config.CLAWGUARD_ADMIN_KEY.encode(),
    )


def bearer(authorization: str | None) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "Bearer credential required", headers={"WWW-Authenticate": "Bearer"})
    return token


def require_agent(authorization: str | None = Header(default=None)) -> str:
    token = bearer(authorization)
    for agent, key in config.CLAWGUARD_AGENT_KEYS.items():
        if key and secrets.compare_digest(token.encode(), key.encode()):
            return agent
    raise HTTPException(401, "Invalid agent credential")


def require_admin(authorization: str | None = Header(default=None)) -> None:
    if not valid_admin(bearer(authorization)):
        raise HTTPException(401, "Invalid admin credential")


def bind_agent(claimed: str, authenticated: str) -> str:
    if claimed not in ("unknown", authenticated):
        raise HTTPException(403, "Credential does not belong to the requested agent")
    return authenticated
