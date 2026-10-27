# Research gateway: acceptance contract

ClawGuard serves developers running research agents against approved HTTPS websites
and APIs. Operators define each agent's tools and exact destination origins. Agents
receive a dedicated credential and use the existing HTTP envelope or Python SDK.

The gateway binds credentials to agent identity, checks every DNS answer, connects
only to a validated address while preserving certificate verification, and returns
only bounded, fully scanned text. Redirects, non-public addresses, unsupported
content encodings, and enforcement failures are blocked. The default research
policy permits read requests; operators explicitly enable other methods.

The admin credential protects the dashboard, audit API, and metrics. New audit
records contain decision metadata and destination origin, not URL paths, queries,
headers, or content. Dashboard credentials stay in browser memory. The demo trigger
is removed from the deployed service.

## Acceptance checks

- A research client retrieves approved clean content through the real transport.
- Missing credentials, identity substitution, and admin access with an agent key fail.
- Disallowed origins/methods/tools and private, loopback, metadata, mixed-address,
  unresolved, and IPv6 destinations cannot cause an upstream connection.
- DNS rebinding cannot change the selected connection address; TLS still verifies
  the original hostname. Redirects do not make a second request.
- Excessive, compressed, invalid text, and timed-out responses never reach the agent.
- A detected injection and a scanner failure both block content.
- Audit storage and live events do not retain secrets from requests or responses.
- Backend and SDK tests run offline after locked install; lint, type checks, SDK
  packaging, and dashboard production build run in CI on push and pull request.
- README provides exact setup, policy, credential, test, and operational commands.

## Scope and limits

Reuse FastAPI, SQLite, Next.js, and the SDK. This is a single-instance gateway for
trusted operators. It cannot control agent traffic that bypasses it; use network
egress restrictions for that guarantee. Prompt-injection detection is heuristic and
can produce false positives and false negatives. Approved services can themselves
leak data or act as proxies, so approval remains an operator decision.

No manufactured history, deployment artifacts without a deployment target, or
payout guarantee. The supplied DataFactor assessment misses existing tests and
Python manifests; build evidence and honest development history are the relevant
improvements. Reclassify the repository as an application/security service.
