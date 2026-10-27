# Contributing

Follow the locked setup and checks in README.md. Never use real API keys, user
content, or public attack targets in tests. Tests must run without external
network services; local TLS fixtures cover the real HTTP transport.

Keep each change focused on one observable behavior and include the regression
test that proves it. Describe the failing case, expected behavior, and commands
you ran in the PR. Conventional commit prefixes such as `fix:`, `feat:`, and
`test:` make intent clear. Do not split cosmetic changes into artificial tasks,
backdate work, or invent contributors to improve history metrics.

When changing a public contract, update the SDK, dashboard, fixtures, examples,
and migration notes that consume it. Security checks may not be bypassed to make
a fixture pass. Tests for rejected traffic should also include an allowed control.

Dependency changes update the appropriate manifest and lock together. Run the
same tests/builds against the locked environment. CI must pass before merging.
SDK releases build from `sdk/`; PyPI publishing requires the repository owner to
configure trusted publishing and the protected `pypi` environment.
