# Security boundaries

ClawGuard is a single-instance gateway for agent requests to operator-approved
HTTPS origins. Agent bearer credentials are not admin credentials. Only trusted
operators may edit policies, environment variables, or the audit database.

Relevant reports include authentication/identity bypass, private-network access,
DNS validation-to-connection gaps, routing-header bypass, unscanned content being
returned, credential disclosure, and resource limits that can be bypassed.

Prompt-injection classification is heuristic. A clean verdict is not proof that
content is safe to execute or follow. The gateway does not control traffic that
bypasses it, sandbox tools, implement tenant isolation, or validate that an
approved public website never proxies requests elsewhere.

Use HTTPS/WSS for remote clients, keep keys in secret storage, rotate by replacing
configuration and restarting, and restrict the gateway host's egress. Keep Groq
disabled unless sending candidate content to that service is approved. Use
infrastructure rate limits, disk monitoring, and a defined SQLite retention policy.

Use GitHub private vulnerability reporting if enabled for this repository. Do not
include live credentials or sensitive research content in a public issue. This
repository currently has no promised response time or external security audit.
