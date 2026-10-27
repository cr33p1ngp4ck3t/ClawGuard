# Research Gateway Implementation Plan

**Goal:** Deliver a reproducible gateway for research agents using approved HTTPS services.
**Architecture:** Retain the proxy envelope and existing policy, detection, and audit layers.
Bind agent credentials at the API boundary and enforce destinations at the transport boundary.
**Tech stack:** Python 3.12+, FastAPI, httpx, SQLite, Next.js, TypeScript, uv.
**Spec:** `docs/research-gateway.md`

## 1. Prove and close gateway boundaries

Files: backend policy models/loader/engine, proxy client/handler, auth, main, scan,
audit logger, config, conftest, and backend tests.

- [x] Run the existing suite after installing its declared test dependencies.
- [x] Add failing tests for missing auth, identity substitution, denied origins,
  private/mixed DNS, response limits, and audit redaction.
- [x] Bind bearer credentials to agent IDs; use a separate admin credential.
- [x] Validate exact HTTPS origins and methods before resolving all addresses.
- [x] Connect to the checked IP with original Host and TLS server name, reject
  redirects/encoded responses, and bound raw streamed bytes and total duration.
- [x] Fail closed on enforcement failures, record one redacted audit event, and
  expose admin-only aggregate metrics.
- [x] Verify local TLS with a trusted test certificate, rebinding, rejection, and
  legitimate control cases using `uv run --project backend pytest backend/tests`.

## 2. Propagate authenticated access

Files: sdk client, decorators, framework adapters and tests; frontend API, socket,
dashboard and components.

- [x] Test SDK gateway bearer credentials separately from upstream headers.
- [x] Add optional `api_key`/`CLAWGUARD_API_KEY` support to all SDK entry points.
- [x] Require a dashboard key, keep it in memory, protect REST and authenticate the
  websocket's first message before subscribing; clear access on signout/auth failure.
- [x] Remove the demo action and expose useful errors and research-oriented copy.
- [x] Run SDK tests and frontend lint, type check, production build and browser checks.

## 3. Reproducible delivery

Files: per-package Python manifests/uv.lock, frontend manifest/lock/lint config,
CI/release workflows, Dependabot, Dockerfiles, compose, README, CONTRIBUTING, SECURITY.

- [x] Rename the backend distribution to avoid colliding with the SDK; lock runtime
  and development dependencies and document `uv sync --locked`/`npm ci`.
- [x] Gate push/PR on tests, lint, type checks, packaging, build and dependency audits.
- [x] Build the SDK from sdk/, and use locked non-root containers with loopback host
  ports and explicit credentials; keep mock targets out of normal deployment.
- [x] Write a runnable research example and migration/operations instructions.
- [x] Review the diff and run relevant checks; report any unavailable Docker runtime
  or remote CI evidence accurately. Leave focused source/tests together for review.
