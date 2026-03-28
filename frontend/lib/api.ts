const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function fetchEvents(
  limit = 50,
  riskLevel?: string,
  agentId?: string
): Promise<{ events: import("./types").AuditEvent[]; count: number }> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (riskLevel) params.set("risk_level", riskLevel);
  if (agentId) params.set("agent_id", agentId);

  const res = await fetch(`${API_BASE}/api/events?${params}`);
  return res.json();
}

export async function fetchStats(): Promise<import("./types").DashboardStats> {
  const res = await fetch(`${API_BASE}/api/stats`);
  return res.json();
}

export async function fetchPolicy(): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/api/policy`);
  return res.json();
}

export async function triggerDemo(): Promise<{
  results: import("./types").DemoResult[];
}> {
  const res = await fetch(`${API_BASE}/api/demo/run`, { method: "POST" });
  return res.json();
}
