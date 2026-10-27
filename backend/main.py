from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

import config
from api.dashboard import router as dashboard_router
from api.scan import router as scan_router
from api.ws import manager
from audit.db import get_stats, init_db
from audit.models import ProxyRequest
from auth import bind_agent, require_admin, require_agent, valid_admin
from limits import RequestLimitMiddleware
from policy.loader import load_policy
from proxy.handler import handle_proxy_request

config.setup_logging()
logger = logging.getLogger('clawguard.main')
app_policy = load_policy(config.POLICY_PATH)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.validate_credentials(set(app_policy.agent_rules))
    await init_db()
    logger.info('ClawGuard research gateway ready')
    yield


app = FastAPI(title='ClawGuard', description='Controlled web access for research agents', version='0.2.0', lifespan=lifespan)
app.add_middleware(RequestLimitMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_credentials=False,
                   allow_methods=['GET', 'POST'], allow_headers=['Authorization', 'Content-Type'])
app.include_router(dashboard_router)
app.include_router(scan_router)


@app.get('/health')
async def health():
    return {'status': 'ok', 'service': 'clawguard'}


@app.post('/proxy')
async def proxy_endpoint(request: ProxyRequest, agent: str = Depends(require_agent)):
    request.agent_id = bind_agent(request.agent_id, agent)
    try:
        return (await handle_proxy_request(request, app_policy)).model_dump()
    except Exception as exc:
        raise HTTPException(503, 'Audit storage unavailable; response withheld') from exc


@app.get('/metrics', dependencies=[Depends(require_admin)], response_class=PlainTextResponse)
async def metrics():
    stats = await get_stats()
    return '\n'.join([
        '# TYPE clawguard_requests_total counter',
        f'clawguard_requests_total {stats["total_requests"]}',
        '# TYPE clawguard_blocked_total counter',
        f'clawguard_blocked_total {stats["blocked_requests"]}',
        '# TYPE clawguard_average_latency_ms gauge',
        f'clawguard_average_latency_ms {stats["avg_latency_ms"]}', '',
    ])


@app.websocket('/api/ws')
async def websocket_endpoint(websocket: WebSocket):
    origin = websocket.headers.get('origin')
    if origin and origin not in config.CORS_ORIGINS:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        message = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        if not isinstance(message, dict) or not isinstance(message.get('token'), str) or not valid_admin(message['token']):
            await websocket.close(code=1008)
            return
        await manager.connect(websocket)
        await websocket.send_json({'type': 'authenticated'})
        while True:
            await websocket.receive_text()
    except (TimeoutError, ValueError, TypeError):
        await websocket.close(code=1008)
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host='127.0.0.1', port=config.PROXY_PORT, limit_concurrency=32)
