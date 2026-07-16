"use client";

import { useCallback, useEffect, useState } from "react";
import {
  clearHistory,
  createCase,
  deleteCase,
  deleteCaseItem,
  getCase,
  getCases,
  getHistory,
  updateCaseItem,
} from "@/lib/api";
import type { CaseDetail, CaseSummary, HistoryEntry } from "@/lib/types";
import MonitorView from "./MonitorView";
import { TrashIcon } from "./icons";

const STATUS_OPTS = ["open", "suspicious", "escalate", "cleared"];
const statusClass: Record<string, string> = {
  open: "border-line bg-surface text-fg-muted",
  suspicious: "border-amber-400/40 bg-amber-400/10 text-amber-400",
  escalate: "border-danger/40 bg-danger/10 text-danger",
  cleared: "border-live/40 bg-live/10 text-live",
};

function when(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function HistoryView() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const load = useCallback(() => {
    getHistory().then(setEntries).catch(() => setEntries([]));
  }, []);
  useEffect(() => load(), [load]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="text-sm text-fg-muted">{entries.length} recent runs</span>
        <button
          type="button"
          onClick={() => clearHistory().then(load)}
          className="text-xs text-fg-faint hover:text-danger"
        >
          Clear history
        </button>
      </div>
      <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
        {entries.length === 0 ? (
          <p className="px-4 py-10 text-center text-sm text-fg-muted">
            No history yet — run a search or a domain tool.
          </p>
        ) : (
          <div className="divide-y divide-line-soft/60">
            {entries.map((h) => (
              <div key={h.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <span className="w-28 shrink-0 rounded border border-line bg-canvas px-2 py-0.5 text-center font-mono text-[11px] text-accent">
                  {h.tool}
                </span>
                <span className="min-w-0 flex-1 truncate font-mono text-fg-muted">
                  {h.input || "—"}
                </span>
                <span className="shrink-0 font-mono text-[11px] text-fg-faint">
                  {Object.entries(h.summary)
                    .map(([k, v]) => `${k}:${v}`)
                    .join(" · ")}
                </span>
                <span className="w-40 shrink-0 text-right text-[11px] text-fg-faint">
                  {when(h.ts)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function CasesView() {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [active, setActive] = useState<CaseDetail | null>(null);
  const [name, setName] = useState("");

  const loadCases = useCallback(() => {
    getCases().then(setCases).catch(() => setCases([]));
  }, []);
  useEffect(() => loadCases(), [loadCases]);

  async function openCase(id: number) {
    setActive(await getCase(id));
  }
  async function refreshActive() {
    if (active) setActive(await getCase(active.id));
  }
  async function create() {
    const n = name.trim();
    if (!n) return;
    const c = await createCase(n);
    setName("");
    loadCases();
    setActive(c);
  }

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[300px_1fr]">
      {/* Case list */}
      <div className="flex flex-col gap-3">
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
            placeholder="New case name…"
            className="flex-1 rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25"
          />
          <button
            type="button"
            onClick={create}
            className="rounded-lg bg-accent-gradient px-3 py-2 text-sm font-semibold text-white shadow-glow"
          >
            Create
          </button>
        </div>
        <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
          {cases.length === 0 ? (
            <p className="px-4 py-8 text-center text-sm text-fg-muted">No cases yet.</p>
          ) : (
            <div className="divide-y divide-line-soft/60">
              {cases.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => openCase(c.id)}
                  className={`flex w-full items-center justify-between px-4 py-2.5 text-left text-sm transition-colors hover:bg-white/[0.03] ${
                    active?.id === c.id ? "bg-accent/10 text-accent" : "text-fg"
                  }`}
                >
                  <span className="truncate">{c.name}</span>
                  <span className="ml-2 shrink-0 font-mono text-[11px] text-fg-faint">
                    {c.item_count}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Case detail */}
      <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
        {!active ? (
          <p className="py-12 text-center text-sm text-fg-muted">
            Select or create a case to view its items.
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-medium text-fg">{active.name}</h3>
              <button
                type="button"
                onClick={async () => {
                  await deleteCase(active.id);
                  setActive(null);
                  loadCases();
                }}
                className="text-xs text-fg-faint hover:text-danger"
              >
                Delete case
              </button>
            </div>
            {active.items.length === 0 ? (
              <p className="py-8 text-center text-sm text-fg-muted">
                No items yet. Add findings from Domain Tools (e.g. Enrich → Add to
                case).
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {active.items.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-start gap-3 rounded-lg border border-line-soft bg-canvas px-3 py-2"
                  >
                    <span className="mt-0.5 shrink-0 rounded border border-line px-1.5 py-px font-mono text-[10px] text-fg-faint">
                      {item.kind}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-sm text-fg">
                        {typeof item.data.domain === "string"
                          ? item.data.domain
                          : JSON.stringify(item.data)}
                      </div>
                      {item.note && (
                        <div className="text-xs text-fg-muted">{item.note}</div>
                      )}
                    </div>
                    <select
                      value={item.status}
                      onChange={async (e) => {
                        await updateCaseItem(item.id, { status: e.target.value });
                        refreshActive();
                      }}
                      className={`shrink-0 rounded border px-1.5 py-0.5 text-xs ${statusClass[item.status] ?? statusClass.open}`}
                    >
                      {STATUS_OPTS.map((s) => (
                        <option key={s} value={s} className="bg-surface-2 text-fg">
                          {s}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={async () => {
                        await deleteCaseItem(item.id);
                        refreshActive();
                      }}
                      className="mt-0.5 text-fg-faint hover:text-danger"
                      title="Remove item"
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default function Workspace() {
  const [view, setView] = useState<"cases" | "monitor" | "history">("cases");
  return (
    <div className="flex flex-col gap-4">
      <div className="flex rounded-lg border border-line bg-canvas p-0.5 text-sm">
        {(["cases", "monitor", "history"] as const).map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => setView(v)}
            className={`rounded-md px-3 py-1 font-medium capitalize transition-colors ${
              view === v ? "bg-accent/15 text-accent" : "text-fg-muted hover:text-fg"
            }`}
          >
            {v}
          </button>
        ))}
      </div>
      {view === "cases" && <CasesView />}
      {view === "monitor" && <MonitorView />}
      {view === "history" && <HistoryView />}
    </div>
  );
}
