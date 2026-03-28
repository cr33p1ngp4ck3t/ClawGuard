import type { RiskLevel } from "@/lib/types";

const RISK_STYLES: Record<RiskLevel, string> = {
  low: "bg-green-500/20 text-green-400 border-green-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase border ${RISK_STYLES[level] || RISK_STYLES.low}`}
    >
      {level}
    </span>
  );
}
