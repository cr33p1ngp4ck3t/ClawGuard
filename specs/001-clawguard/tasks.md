# Tasks: ClawGuard - AI Agent Firewall

**Input**: Design documents from `/specs/001-clawguard/`
**Prerequisites**: spec.md, plan (in plan file)

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project init, dependencies, base config

- [ ] T001 [P] Create backend project structure: `backend/` with subdirs proxy/, detection/, policy/, audit/, api/, demo/, policies/
- [ ] T002 [P] Create `backend/pyproject.toml` and `backend/requirements.txt` with deps: fastapi, uvicorn, httpx, pydantic, aiosqlite, pyyaml, groq
- [ ] T003 [P] Create `backend/config.py` — settings from env vars (GROQ_API_KEY, DB_PATH, PROXY_PORT, CORS origins)
- [ ] T004 [P] Create `.env.example` with all required env vars
- [ ] T005 Create `backend/main.py` — FastAPI app, CORS middleware, health check endpoint, app lifespan (DB init)

**Checkpoint**: `uvicorn main:app --reload` starts without errors

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core models and audit infrastructure that all stories depend on

- [ ] T006 [P] Create `backend/audit/models.py` — RiskLevel, EventType enums + AuditEvent, ProxyRequest, ProxyResponse Pydantic models
- [ ] T007 [P] Create `backend/audit/db.py` — SQLite init (schema creation), insert_event(), query_events(), get_stats() async functions
- [ ] T008 Create `backend/audit/logger.py` — log_event() that writes to DB + broadcasts via WebSocket manager
- [ ] T009 Create `backend/api/ws.py` — WebSocket connection manager (connect, disconnect, broadcast)

**Checkpoint**: Models importable, DB creates tables on startup, WS manager works

---

## Phase 3: User Story 1 - Proxy & Injection Detection (P1) MVP

**Goal**: Requests flow through proxy, responses scanned for injection, threats blocked

**Independent Test**: POST /proxy with injected response -> blocked=true, risk_level=critical

### Implementation

- [ ] T010 Create `backend/proxy/client.py` — async httpx client wrapper (forward_request function)
- [ ] T011 [P] Create `backend/detection/patterns.py` — 8 regex patterns (IGNORE_PREVIOUS, SYSTEM_PROMPT_EXTRACT, ROLE_OVERRIDE, HIDDEN_INSTRUCTION, BASE64_PAYLOAD, DELIMITER_INJECTION, TOOL_CALL_INJECTION, EXFILTRATION_ATTEMPT) with severity levels
- [ ] T012 Create `backend/detection/regex_detector.py` — scan_for_injections(text) -> list[PatternMatch]
- [ ] T013 Create `backend/detection/engine.py` — analyze_content() orchestrator: runs regex, computes aggregate risk, returns DetectionResult
- [ ] T014 Create `backend/proxy/handler.py` — handle_proxy_request(): ingest -> forward -> scan response -> return/block. Wire detection engine + audit logger
- [ ] T015 Wire proxy handler into `backend/main.py` as POST /proxy endpoint
- [ ] T016 Create `backend/demo/mock_server.py` — simple FastAPI app on port 9999 with /echo (clean), /malicious (injection payload), /ssrf-target endpoints

**Checkpoint**: POST /proxy with mock target -> response returns. Malicious response -> blocked=true with pattern matches

---

## Phase 4: User Story 2 - Policy Enforcement (P1)

**Goal**: Requests checked against YAML policies before forwarding, SSRF blocked

**Independent Test**: research-agent + shell.execute -> blocked by policy; request to 169.254.169.254 -> blocked

### Implementation

- [ ] T017 Create `backend/policy/models.py` — ToolPermission, NetworkRule, Policy Pydantic models
- [ ] T018 Create `backend/policies/default.yaml` — research-agent (web only), coding-agent (files+shell), network deny list (internal IPs, metadata endpoint)
- [ ] T019 Create `backend/policy/loader.py` — load_policy(path) -> Policy, with validation
- [ ] T020 Create `backend/policy/engine.py` — evaluate_request(ProxyRequest, Policy) -> PolicyDecision (allow/deny + reason). Tool permission matching (glob patterns) + network CIDR checking
- [ ] T021 Wire policy engine into `backend/proxy/handler.py` — evaluate BEFORE forwarding, block on deny

**Checkpoint**: Unauthorized tool -> 403 + policy_rule. Internal IP -> blocked. Allowed requests pass through

---

## Phase 5: User Story 3 - Real-Time Dashboard (P2)

**Goal**: Next.js dashboard showing live traffic, threats, stats, policy

**Independent Test**: Open dashboard, fire attacks, see events appear in <1 second

### Implementation

- [ ] T022 Create `backend/api/dashboard.py` — GET /api/events (paginated, filterable by risk_level/agent_id), GET /api/stats, GET /api/policy, POST /api/demo/run
- [ ] T023 Wire dashboard routes + WS endpoint into `backend/main.py`
- [ ] T024 Init Next.js frontend: `npx create-next-app@latest frontend --typescript --tailwind --app --no-eslint`
- [ ] T025 [P] Create `frontend/src/lib/types.ts` — TypeScript types matching backend models (AuditEvent, DashboardStats, RiskLevel, etc.)
- [ ] T026 [P] Create `frontend/src/lib/api.ts` — fetchEvents(), fetchStats(), fetchPolicy(), triggerDemo() API client functions
- [ ] T027 Create `frontend/src/hooks/useWebSocket.ts` — WS connection to backend /api/ws, auto-reconnect, message parsing
- [ ] T028 [P] Create `frontend/src/components/RiskBadge.tsx` — color-coded severity badge (green/yellow/orange/red for low/medium/high/critical)
- [ ] T029 [P] Create `frontend/src/components/StatsCards.tsx` — total requests, blocked, threats detected, risk breakdown cards
- [ ] T030 Create `frontend/src/components/TrafficFeed.tsx` — scrolling real-time event list with risk badges, agent_id, tool_name, blocked status
- [ ] T031 [P] Create `frontend/src/components/PolicyView.tsx` — formatted display of active YAML policy
- [ ] T032 Create `frontend/src/components/ThreatTimeline.tsx` — Recharts area chart of events over time by risk level
- [ ] T033 Create `frontend/src/app/page.tsx` — compose all dashboard components, fetch initial data, subscribe to WebSocket
- [ ] T034 Create `frontend/src/app/layout.tsx` — dark theme root layout with ClawGuard branding

**Checkpoint**: Dashboard loads, shows historical events, new events appear live via WS

---

## Phase 6: User Story 4 - Attack Demo Mode (P3)

**Goal**: Self-running demo that fires 3 attack scenarios

### Implementation

- [ ] T035 Create `backend/demo/scenarios.py` — 3 scenario definitions (web scrape injection, SSRF, privilege escalation) with payloads and expected results
- [ ] T036 Create `backend/demo/attacker.py` — async script that runs scenarios against /proxy, prints formatted results
- [ ] T037 Implement POST /api/demo/run in `backend/api/dashboard.py` — triggers demo scenarios and returns results
- [ ] T038 Create `frontend/src/app/demo/page.tsx` — demo page with "Run Attack Demo" button, shows before/after comparison

**Checkpoint**: python -m demo.attacker runs, all 3 attacks blocked, dashboard shows burst of threat events

---

## Phase 7: Polish & Enhancement

**Purpose**: LLM detection, packaging, docs

- [ ] T039 Create `backend/detection/llm_detector.py` — Groq API classifier (llama3), async with 3s timeout, returns LLMClassification
- [ ] T040 Wire LLM detector into `backend/detection/engine.py` — run on medium-risk regex results for semantic confirmation
- [ ] T041 Create `docker-compose.yml` — backend + frontend services
- [ ] T042 Create `README.md` — project description, setup, demo instructions, architecture diagram
- [ ] T043 Create `.gitignore` — Python, Node, .env, SQLite, __pycache__

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No deps — start immediately
- **Phase 2 (Foundational)**: Depends on Phase 1
- **Phase 3 (US1 - Proxy+Detection)**: Depends on Phase 2. BLOCKS Phase 4.
- **Phase 4 (US2 - Policy)**: Depends on Phase 3 (handler.py exists to wire into)
- **Phase 5 (US3 - Dashboard)**: Depends on Phase 2 (API models exist). Can partially overlap Phase 3/4.
- **Phase 6 (US4 - Demo)**: Depends on Phases 3+4 (attacks to demo) and Phase 5 (dashboard to show)
- **Phase 7 (Polish)**: Depends on all prior phases

### Parallel Opportunities

- T001-T004 all parallel (project scaffolding)
- T006-T007 parallel (models + DB)
- T011 parallel with T010 (patterns + client)
- T025-T026 parallel (types + API client)
- T028-T029-T031 parallel (independent components)

### Cut Plan (if behind)

Drop in this order: T039-T040 (LLM) -> T032 (timeline chart) -> T041 (docker) -> T038 (demo page) -> T042 (README polish)
