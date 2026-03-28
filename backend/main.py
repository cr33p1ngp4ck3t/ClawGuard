from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

import config
from api.dashboard import router as dashboard_router
from api.ws import manager
from audit.db import init_db
from audit.models import ProxyRequest
from policy.loader import load_policy
from proxy.handler import handle_proxy_request

app_policy = load_policy(config.POLICY_PATH)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    print(f"ClawGuard started | Policy: {app_policy.name} v{app_policy.version}")
    print(f"Agents configured: {', '.join(app_policy.agent_rules.keys())}")
    print(f"Network rules: {len(app_policy.network_rules)} deny rules active")
    yield


app = FastAPI(
    title="ClawGuard",
    description="AI Agent Firewall - Secure agent-to-tool pipelines",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "clawguard", "policy": app_policy.name}


@app.post("/proxy")
async def proxy_endpoint(request: ProxyRequest):
    response = await handle_proxy_request(request, app_policy)
    return response.model_dump()


@app.post("/api/demo/run")
async def run_demo():
    """Fire all demo attack scenarios against the proxy internally."""
    from demo.scenarios import SCENARIOS

    results = []
    for scenario in SCENARIOS:
        req = ProxyRequest(**scenario["request"])
        resp = await handle_proxy_request(req, app_policy)
        results.append(
            {
                "name": scenario["name"],
                "blocked": resp.blocked,
                "risk_level": resp.risk_level.value,
                "threats_detected": resp.threats_detected,
                "policy_rule": resp.policy_rule,
            }
        )
        await asyncio.sleep(0.5)  # Stagger for visual effect on dashboard
    return {"results": results}


@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=config.PROXY_PORT, reload=True)
