# ClawGuard Constitution

## Core Principles

### I. Security-First
Every design decision prioritizes security correctness over convenience. The proxy must never silently pass through unscanned content. Fail-closed: if detection or policy evaluation errors occur, block the request rather than allow it. No hardcoded secrets or tokens — use environment variables.

### II. Demo-Driven Development
Every feature must be visually demonstrable within 60 seconds. If it can't be shown in a demo video, it's deprioritized. Build the attack scenarios alongside the defenses — the demo IS the product for judging.

### III. MVP Scope Discipline
24-hour hackathon constraint is absolute. No over-engineering, no abstractions for hypothetical future use. Three capabilities only: prompt injection detection, policy enforcement, audit trail. Cut scope before cutting quality.

### IV. Framework-Agnostic Design
ClawGuard works with any AI agent framework. The envelope-based proxy pattern means zero coupling to LangChain, CrewAI, or any specific SDK. Agents send standard HTTP — ClawGuard doesn't care what's behind the request.

### V. Observable by Default
Every agent-tool interaction is logged, risk-scored, and broadcast in real-time. The audit trail is not optional — it's the foundation. The dashboard shows exactly what's happening, no hidden state.

### VI. Layered Defense
Detection uses multiple strategies: fast regex patterns (always active) plus LLM semantic classification (when available). Policy enforcement is a separate layer from content detection. Either can block independently. Defense in depth, not single points of failure.

## Technical Constraints

- **Backend**: Python 3.11+ with FastAPI, async throughout
- **Frontend**: Next.js with TypeScript and Tailwind CSS
- **Database**: SQLite via aiosqlite (zero external dependencies)
- **LLM**: Groq API for semantic classification (optional, regex-only fallback)
- **Communication**: WebSocket for real-time dashboard, REST for queries
- **Proxy pattern**: Envelope-based JSON (explicit target_url, method, body, agent_id, tool_name)

## Development Workflow

- Quick SDD: constitution -> specify -> tasks -> implement
- Smallest viable diff per commit
- PHRs created for every significant interaction
- ADRs only for genuinely architectural decisions (not implementation details)
- Test via demo scenarios: if the attack demo works, the feature works

## Governance

Constitution is the authority for all ClawGuard development decisions. Scope expansion requires explicit justification against the 24-hour constraint. Security correctness is non-negotiable; everything else can be simplified.

**Version**: 1.0.0 | **Ratified**: 2026-03-27 | **Last Amended**: 2026-03-27
