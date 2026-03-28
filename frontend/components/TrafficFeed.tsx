"use client";

import type { AuditEvent } from "@/lib/types";
import { RiskBadge } from "./RiskBadge";

interface TrafficFeedProps {
  events: AuditEvent[];
}

function timeAgo(timestamp: string): string {
  const diff = Date.now() - new Date(timestamp).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  return `${Math.floor(minutes / 60)}h ago`;
}

function eventTypeLabel(eventType: string): string {
  const labels: Record<string, string> = {
    request: "REQUEST",
    response: "PASS",
    policy_block: "POLICY BLOCK",
    injection_detected: "INJECTION",
    injection_blocked: "INJECTION BLOCKED",
  };
  return labels[eventType] || eventType.toUpperCase();
}

export function TrafficFeed({ events }: TrafficFeedProps) {
  if (events.length === 0) {
    return (
      <div className="text-center py-12 text-zinc-500">
        <p className="text-lg">No events yet</p>
        <p className="text-sm mt-1">
          Run the attack demo to see traffic flow through ClawGuard
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
      {events.map((event, i) => (
        <div
          key={event.id}
          className={`rounded-lg border p-3 transition-all duration-300 ${
            event.blocked
              ? "bg-red-500/5 border-red-500/30 animate-in fade-in slide-in-from-top-2"
              : "bg-zinc-800/50 border-zinc-700/50"
          } ${i === 0 ? "ring-1 ring-zinc-600/50" : ""}`}
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <RiskBadge level={event.risk_level} />
              <span className="text-xs font-mono text-zinc-400 truncate">
                {event.agent_id}
              </span>
              <span className="text-zinc-600">-&gt;</span>
              <span className="text-xs font-mono text-zinc-300 truncate">
                {event.tool_name}
              </span>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {event.blocked && (
                <span className="text-xs font-bold text-red-400 bg-red-500/10 px-2 py-0.5 rounded">
                  BLOCKED
                </span>
              )}
              <span className="text-xs text-zinc-500">
                {timeAgo(event.timestamp)}
              </span>
            </div>
          </div>

          <div className="mt-1.5 flex items-center gap-2 text-xs text-zinc-500">
            <span className="font-mono">
              {eventTypeLabel(event.event_type)}
            </span>
            <span className="truncate max-w-[300px]">{event.target_url}</span>
            <span className="ml-auto text-zinc-600">{event.duration_ms}ms</span>
          </div>

          {event.blocked && event.detection_details?.patterns && event.detection_details.patterns.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {event.detection_details.patterns.map((p) => (
                <span
                  key={p}
                  className="text-[10px] font-mono bg-red-500/10 text-red-300 px-1.5 py-0.5 rounded"
                >
                  {p}
                </span>
              ))}
            </div>
          )}

          {event.policy_rule && (
            <p className="mt-1.5 text-xs text-orange-400/80 font-mono truncate">
              Policy: {event.policy_rule}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
