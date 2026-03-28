from __future__ import annotations

import json

import aiosqlite

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    target_url TEXT NOT NULL,
    request_summary TEXT,
    response_summary TEXT,
    blocked INTEGER NOT NULL DEFAULT 0,
    detection_details TEXT,
    policy_rule TEXT,
    duration_ms INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_risk ON audit_events(risk_level);
CREATE INDEX IF NOT EXISTS idx_events_agent ON audit_events(agent_id);
"""


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def insert_event(event: dict) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        detection = event.get("detection_details")
        if detection and isinstance(detection, dict):
            detection = json.dumps(detection)

        await db.execute(
            """INSERT INTO audit_events
            (id, timestamp, agent_id, tool_name, event_type, risk_level,
             target_url, request_summary, response_summary, blocked,
             detection_details, policy_rule, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["id"],
                event["timestamp"],
                event["agent_id"],
                event["tool_name"],
                event["event_type"],
                event["risk_level"],
                event["target_url"],
                event.get("request_summary", ""),
                event.get("response_summary"),
                1 if event.get("blocked") else 0,
                detection,
                event.get("policy_rule"),
                event.get("duration_ms", 0),
            ),
        )
        await db.commit()


async def query_events(
    limit: int = 50,
    offset: int = 0,
    risk_level: str | None = None,
    agent_id: str | None = None,
) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM audit_events WHERE 1=1"
        params: list = []

        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                d = dict(row)
                d["blocked"] = bool(d["blocked"])
                if d["detection_details"]:
                    try:
                        d["detection_details"] = json.loads(d["detection_details"])
                    except json.JSONDecodeError:
                        pass
                results.append(d)
            return results


async def get_stats() -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        total = 0
        blocked = 0
        threats = 0
        avg_latency = 0.0
        risk_breakdown: dict[str, int] = {}

        async with db.execute("SELECT COUNT(*) FROM audit_events") as cur:
            row = await cur.fetchone()
            total = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM audit_events WHERE blocked = 1"
        ) as cur:
            row = await cur.fetchone()
            blocked = row[0] if row else 0

        async with db.execute(
            "SELECT COUNT(*) FROM audit_events WHERE event_type IN ('injection_detected', 'injection_blocked', 'policy_block')"
        ) as cur:
            row = await cur.fetchone()
            threats = row[0] if row else 0

        async with db.execute(
            "SELECT AVG(duration_ms) FROM audit_events"
        ) as cur:
            row = await cur.fetchone()
            avg_latency = float(row[0]) if row and row[0] else 0.0

        async with db.execute(
            "SELECT risk_level, COUNT(*) FROM audit_events GROUP BY risk_level"
        ) as cur:
            async for row in cur:
                risk_breakdown[row[0]] = row[1]

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "threats_detected": threats,
            "risk_breakdown": risk_breakdown,
            "avg_latency_ms": round(avg_latency, 1),
        }
