"use client";

import { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { AuditEvent } from "@/lib/types";

interface ThreatTimelineProps {
  events: AuditEvent[];
}

export function ThreatTimeline({ events }: ThreatTimelineProps) {
  const chartData = useMemo(() => {
    if (events.length === 0) return [];

    // Group events into 10-second buckets
    const buckets: Record<string, { time: string; threats: number; clean: number }> = {};

    events.forEach((e) => {
      const d = new Date(e.timestamp);
      const bucket = new Date(
        Math.floor(d.getTime() / 10000) * 10000
      ).toISOString();

      if (!buckets[bucket]) {
        buckets[bucket] = {
          time: d.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          threats: 0,
          clean: 0,
        };
      }

      if (e.blocked) {
        buckets[bucket].threats++;
      } else {
        buckets[bucket].clean++;
      }
    });

    return Object.values(buckets).slice(-30);
  }, [events]);

  if (chartData.length < 2) {
    return (
      <div className="h-[200px] flex items-center justify-center text-zinc-500 text-sm">
        Waiting for more data points...
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={chartData}>
        <defs>
          <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="cleanGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis
          dataKey="time"
          tick={{ fill: "#71717a", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          tick={{ fill: "#71717a", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#18181b",
            border: "1px solid #3f3f46",
            borderRadius: "8px",
            fontSize: "12px",
          }}
        />
        <Area
          type="monotone"
          dataKey="threats"
          stroke="#ef4444"
          fill="url(#threatGrad)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="clean"
          stroke="#22c55e"
          fill="url(#cleanGrad)"
          strokeWidth={2}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
