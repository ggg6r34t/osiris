"use client";

import { useCallback, useEffect, useState } from "react";
import {
  checkAllTakedowns,
  checkTakedown,
  deleteTakedown,
  getTakedowns,
  updateTakedown,
} from "@/lib/api";
import type { Takedown, TakedownStatus } from "@/lib/types";
import { TrashIcon } from "./icons";

const STATUSES: TakedownStatus[] = [
  "new",
  "reported",
  "acknowledged",
  "monitoring",
  "down",
  "relisted",
  "closed",
  "false_positive",
];

const STATUS_CLASS: Record<string, string> = {
  new: "border-line bg-surface text-fg-muted",
  reported: "border-accent/40 bg-accent/10 text-accent",
  acknowledged: "border-accent/40 bg-accent/10 text-accent",
  monitoring: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  down: "border-live/40 bg-live/10 text-live",
  relisted: "border-danger/40 bg-danger/10 text-danger",
  closed: "border-line bg-surface text-fg-faint",
  false_positive: "border-line bg-surface text-fg-faint",
};

function when(ts: number | null): string {
  return ts ? new Date(ts * 1000).toLocaleString() : "—";
}

function TakedownCard({
  t,
  onChange,
}: {
  t: Takedown;
  onChange: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [checking, setChecking] = useState(false);

  async function recheck() {
    setChecking(true);
    try {
      await checkTakedown(t.id);
      onChange();
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-sm text-fg">{t.domain}</span>
        <select
          value={t.status}
          onChange={async (e) => {
            await updateTakedown(t.id, { status: e.target.value });
            onChange();
          }}
          className={`rounded border px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wider ${
            STATUS_CLASS[t.status] ?? STATUS_CLASS.new
          }`}
        >
          {STATUSES.map((s) => (
            <option key={s} value={s} className="bg-surface-2 text-fg">
              {s}
            </option>
          ))}
        </select>
        {t.age_days != null && (
          <span className="font-mono text-[11px] text-fg-faint">{t.age_days}d open</span>
        )}
        {t.last_state && (
          <span className="font-mono text-[11px] text-fg-faint">last: {t.last_state}</span>
        )}
        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={recheck}
            disabled={checking}
            className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent disabled:opacity-50"
          >
            {checking ? "Checking…" : "Re-check"}
          </button>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="text-xs text-fg-faint hover:text-fg"
          >
            {open ? "Hide" : "Timeline"}
          </button>
          <button
            type="button"
            onClick={async () => {
              await deleteTakedown(t.id);
              onChange();
            }}
            className="text-fg-faint hover:text-danger"
            title="Delete"
          >
            <TrashIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-fg-muted">
        {t.contact && <span>Contact: {t.contact}</span>}
        <span>Reported: {when(t.reported_at)}</span>
        <span>Last checked: {when(t.last_checked)}</span>
      </div>
      {t.note && <p className="mt-1 text-xs text-fg-muted">{t.note}</p>}

      {open && t.events && (
        <div className="mt-3 border-t border-line-soft pt-3">
          <div className="flex flex-col gap-1.5">
            {t.events.map((e) => (
              <div key={e.id} className="flex items-baseline gap-2 text-xs">
                <span className="w-36 shrink-0 font-mono text-fg-faint">{when(e.ts)}</span>
                <span className="shrink-0 rounded border border-line px-1.5 py-px font-mono text-[10px] text-accent">
                  {e.kind}
                </span>
                <span className="text-fg-muted">{e.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function TakedownsView() {
  const [items, setItems] = useState<Takedown[]>([]);
  const [checking, setChecking] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(() => {
    getTakedowns().then(setItems).catch(() => setItems([]));
  }, []);
  useEffect(() => load(), [load]);

  async function checkAll() {
    setChecking(true);
    setMsg(null);
    try {
      const r = await checkAllTakedowns();
      setMsg(
        r.changed.length
          ? `${r.checked} checked · ${r.changed.length} changed: ${r.changed
              .map((c) => `${c.domain}→${c.status}`)
              .join(", ")}`
          : `${r.checked} checked · no changes`,
      );
      load();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Check failed.");
    } finally {
      setChecking(false);
    }
  }

  const openCount = items.filter(
    (t) => !["closed", "false_positive"].includes(t.status),
  ).length;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm text-fg-muted">
          {items.length} tracked · {openCount} open
        </span>
        <div className="flex items-center gap-3">
          {msg && <span className="font-mono text-[11px] text-fg-faint">{msg}</span>}
          <button
            type="button"
            onClick={checkAll}
            disabled={checking || openCount === 0}
            className="rounded-lg bg-accent-gradient px-3 py-1.5 text-xs font-semibold text-white shadow-glow disabled:opacity-50"
          >
            {checking ? "Checking…" : "Re-check all open"}
          </button>
        </div>
      </div>

      <p className="-mt-1 text-xs text-fg-faint">
        Track a domain from the Abuse Router (or Domain Tools). Re-checks auto-flag when a reported domain goes{" "}
        <span className="text-live">down</span> or a down one comes back{" "}
        <span className="text-danger">relisted</span> — also runnable via{" "}
        <code>osiris --check-takedowns</code> (cron), with Telegram/webhook alerts on change.
      </p>

      {items.length === 0 ? (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          No takedowns tracked yet. Run the Abuse Router on a domain and click{" "}
          <span className="text-fg">Track takedown</span>.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {items.map((t) => (
            <TakedownCard key={t.id} t={t} onChange={load} />
          ))}
        </div>
      )}
    </div>
  );
}
