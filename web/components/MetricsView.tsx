"use client";

import { useCallback, useEffect, useState } from "react";
import { getMetrics } from "@/lib/api";
import type { Metrics } from "@/lib/types";

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
      <div className={`font-mono text-3xl font-semibold tabular-nums leading-none ${tone ?? "text-fg"}`}>
        {value}
      </div>
      <div className="mt-1.5 text-[11px] uppercase tracking-wider text-fg-faint">{label}</div>
    </div>
  );
}

function Bars({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
      <div className="mb-3 font-mono text-[11px] uppercase tracking-wider text-accent">{title}</div>
      {entries.length === 0 ? (
        <p className="text-sm text-fg-faint">No data yet.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-center gap-3 text-sm">
              <span className="w-32 shrink-0 truncate font-mono text-xs text-fg-muted">{k}</span>
              <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-canvas ring-1 ring-inset ring-line-soft">
                <div
                  className="h-full rounded-full bg-accent-gradient transition-all duration-500"
                  style={{ width: `${(v / max) * 100}%` }}
                />
              </div>
              <span className="w-8 shrink-0 text-right font-mono text-xs tabular-nums text-fg">{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function MetricsView() {
  const [m, setM] = useState<Metrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getMetrics().then(setM).catch((e) => setError(e instanceof Error ? e.message : "Failed to load metrics."));
  }, []);
  useEffect(() => load(), [load]);

  if (error) return <p className="text-sm text-danger">{error}</p>;
  if (!m) return <p className="text-sm text-fg-muted">Loading metrics…</p>;

  const mttr = m.takedowns.mttr_days_mean;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <span className="text-sm text-fg-muted">Operational KPIs over your local cases, takedowns & activity.</span>
        <button type="button" onClick={load} className="text-xs text-fg-faint hover:text-accent">
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Stat label="Open takedowns" value={m.takedowns.open} tone={m.takedowns.open ? "text-amber-300" : "text-fg"} />
        <Stat
          label="Relisted"
          value={m.takedowns.relisted}
          tone={m.takedowns.relisted ? "text-danger" : "text-fg"}
        />
        <Stat
          label="MTTR (days)"
          value={mttr == null ? "—" : mttr}
          tone="text-live"
        />
        <Stat label="Cases" value={m.cases.total} />
        <Stat label="Runs logged" value={m.history.total} />
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Bars title="Takedowns by status" data={m.takedowns.by_status} />
        <Bars title="Open takedown aging (days)" data={m.takedowns.aging} />
        <Bars title="Case items by status" data={m.cases.items_by_status} />
        <Bars title="Activity by tool" data={m.history.by_tool} />
      </div>

      <p className="text-xs text-fg-faint">
        MTTR = mean days from <span className="text-fg">reported</span> to{" "}
        <span className="text-fg">down</span> across {m.takedowns.resolved_count} resolved takedown(s).
        Median: {m.takedowns.mttr_days_median ?? "—"} days.
      </p>
    </div>
  );
}
