"use client";

import { useCallback, useEffect, useState } from "react";
import { addWatch, getWatchlist, removeWatch, runMonitor } from "@/lib/api";
import type { MonitorReport, WatchTarget } from "@/lib/types";

function ToolReport({
  tool,
  r,
}: {
  tool: string;
  r: MonitorReport["report"][string];
}) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-line-soft bg-canvas px-3 py-2">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] uppercase tracking-wider text-accent">
          {tool}
        </span>
        <span className="font-mono text-[11px] text-fg-faint">
          {r.current.length} current
        </span>
      </div>
      {r.first_run ? (
        <span className="text-xs text-fg-muted">Baseline saved.</span>
      ) : r.new.length === 0 && r.gone.length === 0 ? (
        <span className="text-xs text-live">No change since last run.</span>
      ) : (
        <div className="flex flex-col gap-1">
          {r.new.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-medium text-danger">
                {r.new.length} NEW
              </span>
              {r.new.slice(0, 20).map((d) => (
                <span
                  key={d}
                  className="rounded border border-danger/40 bg-danger/10 px-1.5 py-px font-mono text-[10px] text-danger"
                >
                  {d}
                </span>
              ))}
            </div>
          )}
          {r.gone.length > 0 && (
            <span className="text-xs text-fg-faint">
              {r.gone.length} gone: {r.gone.slice(0, 8).join(", ")}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

export default function MonitorView() {
  const [watchlist, setWatchlist] = useState<WatchTarget[]>([]);
  const [target, setTarget] = useState("");
  const [reports, setReports] = useState<Record<string, MonitorReport>>({});
  const [running, setRunning] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getWatchlist().then(setWatchlist).catch(() => setWatchlist([]));
  }, []);
  useEffect(() => load(), [load]);

  async function add() {
    const t = target.trim();
    if (!t) return;
    setError(null);
    try {
      setWatchlist(await addWatch(t));
      setTarget("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add target.");
    }
  }

  async function run(t: string) {
    setRunning((r) => ({ ...r, [t]: true }));
    setError(null);
    try {
      const report = await runMonitor(t);
      setReports((rs) => ({ ...rs, [t]: report }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Monitor run failed.");
    } finally {
      setRunning((r) => ({ ...r, [t]: false }));
    }
  }

  async function remove(t: string) {
    setWatchlist(await removeWatch(t));
    setReports((rs) => {
      const next = { ...rs };
      delete next[t];
      return next;
    });
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder="Watch a domain (e.g. paypal.com)…"
          className="flex-1 rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25"
        />
        <button
          type="button"
          onClick={add}
          className="rounded-lg bg-accent-gradient px-3 py-2 text-sm font-semibold text-white shadow-glow"
        >
          Watch
        </button>
      </div>

      <p className="-mt-2 text-xs text-fg-faint">
        Re-runs Domain Match + DNSTwist and highlights newly-registered lookalikes
        since the last run. Also runnable from the CLI: <code>osiris --monitor</code> (cron-friendly).
      </p>

      {error && <p className="text-sm text-danger">{error}</p>}

      {watchlist.length === 0 ? (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          No watched targets yet. Add a domain to monitor it for new lookalikes.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {watchlist.map((w) => (
            <div
              key={w.id}
              className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm text-fg">{w.target}</span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => run(w.target)}
                    disabled={running[w.target]}
                    className="rounded-md bg-accent-gradient px-3 py-1.5 text-xs font-semibold text-white shadow-glow disabled:opacity-50"
                  >
                    {running[w.target] ? "Running…" : "Run monitor"}
                  </button>
                  <button
                    type="button"
                    onClick={() => remove(w.target)}
                    className="text-xs text-fg-faint hover:text-danger"
                  >
                    Remove
                  </button>
                </div>
              </div>
              {reports[w.target] && (
                <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                  {Object.entries(reports[w.target].report).map(([tool, r]) => (
                    <ToolReport key={tool} tool={tool} r={r} />
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
