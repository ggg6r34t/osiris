"use client";

import { useCallback, useEffect, useState } from "react";
import { getPlaybooks, runPlaybook } from "@/lib/api";
import type { PlaybookDef, PlaybookReport } from "@/lib/types";

const RISK_STYLE: Record<string, string> = {
  high: "border-danger/40 bg-danger/10 text-danger",
  medium: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  low: "border-live/40 bg-live/10 text-live",
  unknown: "border-line bg-surface-2 text-fg-faint",
};

function statusIcon(status: string) {
  if (status === "ok") return <span className="text-live">✓</span>;
  if (status === "error") return <span className="text-danger">✗</span>;
  return <span className="text-fg-faint">–</span>;
}

export default function PlaybooksView() {
  const [defs, setDefs] = useState<PlaybookDef[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [target, setTarget] = useState("");
  const [report, setReport] = useState<PlaybookReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getPlaybooks()
      .then((d) => {
        setDefs(d);
        if (d[0]) setSelected((s) => s || d[0].id);
      })
      .catch(() => setDefs([]));
  }, []);
  useEffect(() => load(), [load]);

  const active = defs.find((d) => d.id === selected);

  async function run() {
    if (!target.trim() || !selected) return;
    setRunning(true);
    setError(null);
    setReport(null);
    try {
      setReport(await runPlaybook(selected, target.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Playbook failed.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Playbook picker */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {defs.map((d) => (
          <button
            key={d.id}
            type="button"
            onClick={() => setSelected(d.id)}
            className={`rounded-2xl border p-4 text-left shadow-card transition-all ${
              d.id === selected
                ? "border-accent/40 bg-gradient-to-b from-accent/15 to-accent/5 ring-1 ring-inset ring-accent/20"
                : "border-line bg-surface/60 hover:border-line hover:bg-surface-2"
            }`}
          >
            <div className="text-sm font-semibold text-fg">{d.name}</div>
            <p className="mt-1 text-xs text-fg-muted">{d.description}</p>
          </button>
        ))}
      </div>

      {/* Run bar */}
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder={active?.target_label || "target"}
          className="flex-1 rounded-lg border border-line bg-canvas px-3 py-2.5 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
        />
        <button
          type="button"
          onClick={run}
          disabled={running || !target.trim()}
          className="rounded-lg bg-accent-gradient px-5 py-2.5 text-sm font-semibold text-white shadow-glow disabled:opacity-40"
        >
          {running ? "Running…" : "Run playbook"}
        </button>
      </div>

      {running && (
        <div className="flex items-center justify-center gap-3 rounded-xl border border-line bg-surface/40 px-4 py-12 text-sm text-fg-muted">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-fg-faint/40 border-t-fg-muted" />
          Running {active?.name}… this chains several tools and can take a bit.
        </div>
      )}
      {!running && error && <p className="text-sm text-danger">{error}</p>}

      {!running && report && (
        <div className="animate-fade-in flex flex-col gap-4">
          {/* Risk + case */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${RISK_STYLE[report.risk.level]}`}>
                {report.risk.level} risk
              </span>
              <span className="font-mono text-sm text-fg">{report.target}</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-fg-muted">
              {report.case_id && <span>Filed to case #{report.case_id}</span>}
              {report.takedown_id && <span className="text-danger">Takedown #{report.takedown_id} opened</span>}
            </div>
          </div>

          {/* Steps */}
          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-accent">
              Steps
            </div>
            <div className="divide-y divide-line-soft/60">
              {report.steps.map((s) => (
                <div key={s.key} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                  <span className="w-4 shrink-0 text-center">{statusIcon(s.status)}</span>
                  <span className="w-64 shrink-0 truncate text-fg">{s.label}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">{s.summary}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Reasons */}
          {report.risk.reasons.length > 0 && (
            <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
              <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-accent">Why this risk</div>
              <ul className="flex flex-col gap-1 text-sm text-fg-muted">
                {report.risk.reasons.map((r, i) => (
                  <li key={i}>• {r}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Candidates (brand playbook) */}
          {report.candidates && report.candidates.length > 0 && (
            <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
              <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-accent">
                {report.candidates.length} candidate lookalikes
              </div>
              <div className="max-h-64 divide-y divide-line-soft/60 overflow-y-auto">
                {report.candidates.map((c) => (
                  <div key={c} className="px-4 py-1.5 font-mono text-sm text-fg">{c}</div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {report.recommendations.length > 0 && (
            <div className="rounded-2xl border border-accent/30 bg-accent/[0.06] p-4">
              <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-accent">Recommended next actions</div>
              <ul className="flex flex-col gap-1.5 text-sm text-fg">
                {report.recommendations.map((r, i) => (
                  <li key={i}>→ {r}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {!running && !report && !error && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Pick a playbook and enter a target to run the full workflow in one click.
        </p>
      )}
    </div>
  );
}
