"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import type { AuditEvent, DashboardStats } from "@/lib/types";
import { ApiError, fetchEvents, fetchStats } from "@/lib/api";
import { useWebSocket } from "@/hooks/useWebSocket";
import { StatsCards } from "@/components/StatsCards";
import { TrafficFeed } from "@/components/TrafficFeed";
import { ThreatTimeline } from "@/components/ThreatTimeline";

const EMPTY_STATS: DashboardStats = {
  total_requests: 0,
  blocked_requests: 0,
  threats_detected: 0,
  risk_breakdown: {},
  avg_latency_ms: 0,
};

export default function Dashboard() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [stats, setStats] = useState<DashboardStats>(EMPTY_STATS);
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [liveError, setLiveError] = useState("");
  const [loading, setLoading] = useState(false);
  const [refresh, setRefresh] = useState(0);

  const signOut = useCallback(() => {
    setApiKey("");
    setEvents([]);
    setStats(EMPTY_STATS);
    setLoading(false);
    setLiveError("");
  }, []);

  const handleError = useCallback((message: string, unauthorized: boolean) => {
    setError(message);
    if (unauthorized) signOut();
  }, [signOut]);

  const handleFetchError = useCallback((cause: unknown) => {
    const unauthorized = cause instanceof ApiError && [401, 403].includes(cause.status);
    handleError(cause instanceof Error ? cause.message : "Unable to load ClawGuard data", unauthorized);
  }, [handleError]);

  const handleLiveError = useCallback((message: string, unauthorized: boolean) => {
    if (unauthorized) handleError(message, true);
    else setLiveError(message);
  }, [handleError]);

  useEffect(() => {
    if (!apiKey) return;
    const controller = new AbortController();
    fetchEvents(apiKey, 100, undefined, undefined, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setEvents(data.events);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) handleFetchError(cause);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [apiKey, handleFetchError]);

  useEffect(() => {
    if (!apiKey) return;
    const controller = new AbortController();
    fetchStats(apiKey, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setStats(data);
      })
      .catch((cause) => {
        if (!controller.signal.aborted) handleFetchError(cause);
      });
    return () => controller.abort();
  }, [apiKey, refresh, handleFetchError]);

  const handleNewEvent = useCallback((event: AuditEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, 200));
    setRefresh((prev) => prev + 1);
  }, []);

  const { connected } = useWebSocket(apiKey, handleNewEvent, handleLiveError);

  const handleConnect = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const input = event.currentTarget.elements.namedItem("admin-key") as HTMLInputElement;
    const key = input.value.trim();
    if (!key) return;
    setError("");
    setLoading(true);
    setApiKey(key);
    input.value = "";
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
              <p className="text-xs text-zinc-500">Research Agent Gateway</p>
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
              onClick={() => { signOut(); setError(""); }}
              disabled={!apiKey}
              className="px-4 py-1.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors cursor-pointer"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {error && (
          <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300">{error}</p>
        )}
        {liveError && (
          <p role="status" className="rounded-lg border border-zinc-700 bg-zinc-900 p-3 text-sm text-zinc-300">{liveError}</p>
        )}
        {!apiKey ? (
          <form onSubmit={handleConnect} className="max-w-md mx-auto rounded-lg border border-zinc-800 bg-zinc-900/50 p-6 space-y-4">
            <div>
              <h2 className="font-semibold text-zinc-100">Connect to your gateway</h2>
              <p className="text-sm text-zinc-400 mt-2">Monitor requests from research agents to approved websites and APIs.</p>
            </div>
            <div>
              <label htmlFor="admin-key" className="block text-sm text-zinc-300 mb-2">Admin key</label>
              <input id="admin-key" name="admin-key" type="password" required autoComplete="off" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:ring-2 focus:ring-red-500" />
              <p className="text-xs text-zinc-500 mt-2">Kept in memory for this session. Sign out to clear it.</p>
            </div>
            <button type="submit" className="w-full rounded-lg bg-red-600 hover:bg-red-700 px-4 py-2 text-sm font-medium text-white cursor-pointer">Connect</button>
          </form>
        ) : (
          <>
            {loading && <p role="status" className="text-sm text-zinc-400">Loading gateway activity…</p>}
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
          </>
        )}
      </main>
    </div>
  );
}
