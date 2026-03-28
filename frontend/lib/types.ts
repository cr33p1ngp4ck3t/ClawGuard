export type RiskLevel = "low" | "medium" | "high" | "critical";
export type EventType =
  | "request"
  | "response"
  | "policy_block"
  | "injection_detected"
  | "injection_blocked";

export interface AuditEvent {
  id: string;
  timestamp: string;
  agent_id: string;
  tool_name: string;
  event_type: EventType;
  risk_level: RiskLevel;
  target_url: string;
  request_summary: string;
  response_summary: string | null;
  blocked: boolean;
  detection_details: {
    patterns?: string[];
    confidence?: number;
    llm_explanation?: string | null;
    scan_duration_ms?: number;
  } | null;
  policy_rule: string | null;
  duration_ms: number;
}

export interface DashboardStats {
  total_requests: number;
  blocked_requests: number;
  threats_detected: number;
  risk_breakdown: Record<string, number>;
  avg_latency_ms: number;
}

export interface DemoResult {
  name: string;
  blocked: boolean;
  risk_level: RiskLevel;
  threats_detected: string[];
  policy_rule: string | null;
}

export interface WebSocketMessage {
  type: "new_event" | "stats_update";
  payload: AuditEvent | DashboardStats;
}
