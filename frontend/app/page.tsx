"use client";

import { useCallback, useEffect, useState } from "react";
import type { AuditEvent, DashboardStats } from "@/lib/types";
import { fetchEvents, fetchStats, triggerDemo } from "@/lib/api";
import { useWebSocket } from "@/hooks/useWebSocket";
import { StatsCards } from "@/components/StatsCards";
import { TrafficFeed } from "@/components/TrafficFeed";
import { ThreatTimeline } from "@/components/ThreatTimeline";

export default function Dashboard() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    total_requests: 0,
    blocked_requests: 0,
    threats_detected: 0,
    risk_breakdown: {},
    avg_latency_ms: 0,
  });
  const [demoRunning, setDemoRunning] = useState(false);

  // Load initial data
  useEffect(() => {
    fetchEvents(100).then((data) => setEvents(data.events)).catch(() => {});
    fetchStats().then(setStats).catch(() => {});
  }, []);

  // Handle real-time WebSocket events
  const handleNewEvent = useCallback((event: AuditEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, 200));
    fetchStats().then(setStats).catch(() => {});
  }, []);

  const { connected } = useWebSocket(handleNewEvent);

  const handleRunDemo = async () => {
    setDemoRunning(true);
    try {
      await triggerDemo();
    } finally {
      setDemoRunning(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-red-500/20 border border-red-500/30 flex items-center justify-center">
              <span className="text-red-400 font-bold text-sm">CG</span>
            </div>
            <div>
              <h1 className="text-lg font-bold text-zinc-100">ClawGuard</h1>
              <p className="text-xs text-zinc-500">AI Agent Firewall</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div
                className={`w-2 h-2 rounded-full ${connected ? "bg-green-400" : "bg-red-400"}`}
              />
              <span className="text-xs text-zinc-500">
                {connected ? "Live" : "Disconnected"}
              </span>
            </div>

            <button
              onClick={handleRunDemo}
              disabled={demoRunning}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-700 disabled:bg-zinc-700 disabled:text-zinc-500 text-white text-sm font-medium rounded-lg transition-colors cursor-pointer"
            >
              {demoRunning ? "Running..." : "Run Attack Demo"}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <StatsCards stats={stats} />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Traffic Feed */}
          <div className="lg:col-span-2">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-zinc-300">
                  Live Traffic Feed
                </h2>
                <span className="text-xs text-zinc-500">
                  {events.length} events
                </span>
              </div>
              <TrafficFeed events={events} />
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">
                Threat Timeline
              </h2>
              <ThreatTimeline events={events} />
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
              <h2 className="text-sm font-semibold text-zinc-300 mb-3">
                Risk Breakdown
              </h2>
              {Object.keys(stats.risk_breakdown).length > 0 ? (
                <div className="space-y-2">
                  {Object.entries(stats.risk_breakdown).map(([level, count]) => (
                    <div key={level} className="flex items-center justify-between">
                      <span className="text-xs text-zinc-400 uppercase">
                        {level}
                      </span>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              level === "critical"
                                ? "bg-red-500"
                                : level === "high"
                                  ? "bg-orange-500"
                                  : level === "medium"
                                    ? "bg-yellow-500"
                                    : "bg-green-500"
                            }`}
                            style={{
                              width: `${Math.min(
                                (count / Math.max(stats.total_requests, 1)) * 100,
                                100
                              )}%`,
                            }}
                          />
                        </div>
                        <span className="text-xs text-zinc-300 font-mono w-6 text-right">
                          {count}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-zinc-500">No data yet</p>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
