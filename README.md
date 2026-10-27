# ClawGuard

Controlled web access for research agents. Give an agent a dedicated key, approve
its HTTPS destinations, and route its fetches through ClawGuard. Operators can see
which requests passed, which were blocked, and why.

For example, a company research assistant can retrieve Wikipedia and an approved
search API, while requests to cloud metadata, internal services, or unapproved
websites are rejected. Returned UTF-8 text is size-limited and checked for prompt
injection before the agent receives it.

ClawGuard is a FastAPI application, Next.js dashboard, and Python SDK. It is
self-hosted application software, not an infrastructure-as-code repository.

## What is enforced

- A bearer key binds every proxy/scan request to one configured agent. A separate
  admin key protects policy, audit records, metrics, and live dashboard updates.
- Exact HTTPS origins and allowed tools/methods are checked before connecting.
  The sample policy permits GET/HEAD to `example.com` and `en.wikipedia.org`.
- Every resolved IPv4/IPv6 address must be public. Connections use the checked IP
  with the original Host and TLS server name, preventing DNS changes between
  validation and connection from redirecting the request to an internal address.
- Redirects are blocked. Request framing/routing headers cannot be overridden.
- Responses must declare a supported text/JSON/XML content type and contain UTF-8
  text. Compressed responses are rejected; the gateway requests identity encoding.
  Responses over the policy byte limit are blocked in full, never partially scanned
  and then returned in full. Total forwarding time is limited to 10 seconds.
- Policy/transport/scanner failures withhold content. Audit-write failures return
  HTTP 503. Audit events retain decision metadata and destination origin, without
  body content, headers, URL paths, or query strings.

**Boundary:** agents must actually use this gateway. Restrict their direct network
access if you need enforced egress. An approved site can still host malicious data
or act as a proxy. Injection detection is heuristic: false positives and false
negatives remain possible. ClawGuard does not sandbox shell commands, execute tools,
protect arbitrary file access, or guarantee that an LLM follows instructions.

## Start locally

Install Python 3.12+ (3.14 is also tested by CI), uv 0.12.1, and Node.js 24.
From a fresh clone:

```sh
git clone https://github.com/cr33p1ngp4ck3t/ClawGuard
cd ClawGuard
uv sync --directory backend --locked
uv sync --directory sdk --locked
npm ci --prefix frontend
```

Copy `.env.example` to `.env`. Generate two different random keys:

```sh
python -c "import secrets; print(secrets.token_urlsafe(32)); print(secrets.token_urlsafe(32))"
```

Set the first as `CLAWGUARD_ADMIN_KEY` and use the second in BOTH the agent-key
mapping and the SDK variable. These are examples of the shape, not working keys:

```dotenv
CLAWGUARD_ADMIN_KEY=<first-generated-value>
CLAWGUARD_AGENT_KEYS='{"research-agent":"<second-generated-value>"}'
CLAWGUARD_API_KEY=<second-generated-value>
```

Keys must be distinct ASCII tokens of at least 32 characters. Missing, duplicate,
or unknown-agent credentials prevent startup. Keep `.env` private.

Start the backend from the repository root:

```sh
uv run --directory backend --env-file ../.env --no-sync python -m uvicorn main:app --host 127.0.0.1 --port 8000 --limit-concurrency 32 --ws-max-size 8192
```

In another terminal:

```sh
npm run dev --prefix frontend
```

Open <http://localhost:3000> and enter the **admin** key. The dashboard holds the
key in memory only; refresh or sign out to clear it. Health is available at
<http://localhost:8000/health>. The SDK uses the **agent** key.

Run the included research fetch from the repository root:

```sh
uv run --directory sdk --env-file ../.env --no-sync python ../examples/research.py https://example.com
```

The example prints a safe response, or a useful blocked/error message and nonzero
exit code. Requests to an unapproved origin will be rejected before any connection.

## Configure approved sources

Edit `backend/policies/default.yaml`, then restart the backend. Approval is an exact
scheme/host/port match; subdomains require their own entry. HTTPS is required.

```yaml
name: Research sources
version: "2.0"
agent_rules:
  research-agent:
    - tool_name: web_fetch
      allowed: true
allowed_origins:
  research-agent:
    - https://en.wikipedia.org
    - https://api.your-approved-provider.com
allowed_methods:
  research-agent: [GET, HEAD]
max_response_size_kb: 512
```

For a search API that needs POST, add POST explicitly for that agent. Keep search
API credentials in the caller's secret store; include them in the envelope's
`headers`. The gateway key belongs in the outer Authorization header and is never
forwarded automatically. GET/HEAD cannot carry a request body. Limits allow up to
1 MiB for the inbound JSON envelope and 1 MiB for configured response size.

Optional `network_rules` may add explicit host/CIDR denials. They cannot override
the public-address restriction. Unknown policy keys and unsupported conditions
fail validation so configuration mistakes cannot silently remove a restriction.

## Python integration

```python
from clawguard import ClawGuardClient

client = ClawGuardClient(agent_id="research-agent")  # CLAWGUARD_API_KEY
result = client.check_sync(
    target_url="https://en.wikipedia.org/w/api.php?action=query&format=json&titles=Solar_energy",
    tool_name="web_fetch",
    headers={"User-Agent": "YourResearchApp/1.0 (your-contact-url)"},
    raise_on_block=True,
)
print(result.body)
```

Async callers use `await client.check(...)`. `RequestBlockedError` indicates a
blocked result; `ClawGuardError` covers transport, authentication, and malformed
responses. With `raise_on_block=False`, always inspect `result.blocked` before using
the body. Upstream HTTP status remains in `result.status_code`; a non-2xx upstream
response is not a successful research result merely because it passed scanning.

`protect()` and the framework helpers accept `api_key` or use the environment.
The LangChain URL-fetch helper takes an explicit URL; it does not turn a free-text
query into an invented search API. Detection-only `/api/scan` checks content but
cannot undo side effects from a tool that already ran.

## API

| Endpoint | Credential | Result |
| --- | --- | --- |
| `GET /health` | None | Process health |
| `POST /proxy` | Agent | Proxy response envelope |
| `POST /api/scan` | Agent | Detection result |
| `GET /api/events` | Admin | Paginated redacted audit events |
| `GET /api/stats` | Admin | Audit aggregates |
| `GET /api/policy` | Admin | Active policy, no keys |
| `GET /metrics` | Admin | Prometheus text aggregates |
| `WS /api/ws` | Admin | First message `{"token":"..."}`, then authenticated ack and events |

Proxy JSON fields: `target_url`, `tool_name`, optional `method` (GET default),
`headers`, `body`, `agent_id`. Omit `agent_id` to use the authenticated identity;
a different supplied identity returns HTTP 403. Missing/invalid keys return 401;
invalid input returns 422; oversized envelopes return 413.

For compatibility, completed proxy decisions return HTTP 200 with an envelope
containing `status_code`, `body`, `blocked`, `risk_level`, `threats_detected`, and
`policy_rule`. A policy block has envelope status 403; a transport/content rule
block has 422; an enforcement failure has 503. Audit failure returns actual HTTP
503 without the upstream content. SDK callers should use the blocked flag or
`raise_on_block=True`.

## Configuration

| Variable | Default / purpose |
| --- | --- |
| `CLAWGUARD_ADMIN_KEY` | Required dashboard/admin bearer token |
| `CLAWGUARD_AGENT_KEYS` | Required JSON object mapping configured agents to unique keys |
| `CLAWGUARD_API_KEY` | SDK bearer token |
| `DB_PATH` | `clawguard.db`; use a writable persistent directory |
| `POLICY_PATH` | Absolute bundled `backend/policies/default.yaml` |
| `CORS_ORIGINS` | `http://localhost:3000`, comma-separated |
| `PROXY_PORT` | `8000` when starting `python main.py`; uvicorn CLI uses `--port` |
| `LOG_LEVEL` | `INFO`, JSON logs to stdout |
| `GROQ_API_KEY` | Empty; optional semantic classification sends candidate content to Groq |
| `LLM_TIMEOUT` | `3` seconds |
| `LLM_MODEL` | `llama-3.3-70b-versatile` |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000`, public dashboard backend address |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8000/api/ws`, public live endpoint |

Keep Groq disabled when research content must remain local. Regex scanning remains
active when Groq is absent/unavailable. Frontend public variables are embedded at
build time; for local development place overrides in `frontend/.env.local`, and
for Compose set them in the root `.env` and rebuild. Never put keys in public vars.

## Docker Compose

After configuring `.env`:

```sh
docker compose up --build -d
docker compose logs -f backend
```

Both containers run as unprivileged users. Host ports bind to loopback. The SQLite
volume persists across restarts; policy files mount read-only. For remote use,
terminate HTTPS/WSS at a trusted reverse proxy, set exact CORS/public URLs, and
rebuild. Keep one backend process: SQLite and live subscriptions are designed for
one instance. Limit ingress at the reverse proxy and monitor disk usage. The
health endpoint is liveness, not proof that every upstream dependency works.

## Tests and quality gates

After the locked install, tests use local fixtures and need no Groq key or external
API. The transport suite starts a local TLS server to verify certificate checks.

```sh
uv run --directory backend --no-sync pytest -q
uv run --directory backend --no-sync ruff check .
uv run --directory backend --no-sync mypy
uv run --directory sdk --no-sync pytest -q
uv run --directory sdk --no-sync ruff check .
uv run --directory sdk --no-sync mypy
uv run --directory sdk --no-sync python -m build --no-isolation
npm test --prefix frontend
npm run lint --prefix frontend
npm run typecheck --prefix frontend
npm run build --prefix frontend
```

CI runs these on push and pull request, audits dependencies, and builds containers.
Python CI covers 3.12 and 3.14. Dependency audits require network access and a
registry response. `uv.lock` files and `frontend/package-lock.json` are committed
inputs; do not regenerate them during CI. Use `uv lock --upgrade` or explicit npm
updates for reviewed dependency changes. Dependabot checks weekly.

## Migrating the hackathon version

1. Add distinct admin and per-agent keys and update every caller.
2. Replace the old sample policy with explicit approved origins and read methods.
   Remove unused `conditions` and `allow` network rules; they now fail validation.
3. Use the real gateway flow. The deployed `/api/demo/run` endpoint is removed;
   attack cases remain in tests. Internal/HTTP mock destinations are intentionally
   incompatible with production research policy.
4. Back up the old SQLite file. New writes and API reads redact content, but old
   rows/backups can still contain historical plaintext. Apply your own retention
   policy or start with a new database after archiving the old one securely.
5. Restart to rotate credentials or reload policy. Rollback requires the prior
   code, dependencies, policy, and credential/client configuration together.

See [CONTRIBUTING.md](CONTRIBUTING.md) for focused changes and verification, and
[SECURITY.md](SECURITY.md) for security boundaries. Real tests, reproducible builds,
and focused fixes support engineering-task review; neither this project nor these
changes guarantee DataFactor acceptance or payout. Sustained development history
must come from real maintenance.
