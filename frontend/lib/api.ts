const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function get<T>(path: string, apiKey: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    cache: "no-store",
    signal,
  });
  let data;
  try {
    data = await res.json();
  } catch {
    throw new ApiError(res.ok ? "ClawGuard returned an invalid response" : `ClawGuard returned HTTP ${res.status}`, res.status);
  }
  if (!res.ok) {
    throw new ApiError(typeof data?.detail === "string" ? data.detail : `ClawGuard returned HTTP ${res.status}`, res.status);
  }
  return data as T;
}

export async function fetchEvents(
  apiKey: string,
  limit = 50,
  riskLevel?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<{ events: import("./types").AuditEvent[]; count: number }> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (riskLevel) params.set("risk_level", riskLevel);
  if (agentId) params.set("agent_id", agentId);

  return get(`/api/events?${params}`, apiKey, signal);
}

export async function fetchStats(apiKey: string, signal?: AbortSignal): Promise<import("./types").DashboardStats> {
  return get("/api/stats", apiKey, signal);
}

export async function fetchPolicy(apiKey: string): Promise<Record<string, unknown>> {
  return get("/api/policy", apiKey);
}
