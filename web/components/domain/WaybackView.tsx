"use client";

import { useState } from "react";
import { waybackHistory } from "@/lib/api";
import type { WaybackResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function WaybackView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<WaybackResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => waybackHistory(target))}
        loading={loading}
        placeholder="example.com"
        button="History"
        hint="Summarizes a domain's Wayback Machine (archive.org) history — first/last capture, years archived, and a per-year snapshot timeline. Keyless."
      />

      {loading && <ToolLoading label="Querying the Wayback Machine…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && !data.found && (
        <div className="rounded-xl border border-line bg-surface/40 px-4 py-8 text-center text-sm text-fg-muted">
          {data.error ? data.error : `No Wayback captures found for ${data.domain}.`}{" "}
          <a href={data.overview_url} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
            Open archive.org ↗
          </a>
        </div>
      )}

      {!loading && data && data.found && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm text-fg">{data.domain}</span>
              <span className="rounded-md border border-line bg-surface-2 px-2 py-0.5 font-mono text-[11px] text-fg-muted">
                {data.years} year{data.years === 1 ? "" : "s"} archived
              </span>
            </div>
            <div className="flex items-center gap-2">
              <a
                href={data.overview_url}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent"
              >
                archive.org calendar ↗
              </a>
              <AddToCase kind="wayback" data={{ domain: data.domain, first: data.first?.date, last: data.last?.date, years: data.years }} />
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Card title="First capture">
              {data.first ? (
                <>
                  <KV k="Date" v={data.first.date} />
                  <KV k="Snapshot" v={<a href={data.first.url} target="_blank" rel="noopener noreferrer" className="break-all font-mono text-xs text-accent hover:underline">open ↗</a>} />
                </>
              ) : (
                <p className="text-sm text-fg-faint">—</p>
              )}
            </Card>
            <Card title="Last capture">
              {data.last ? (
                <>
                  <KV k="Date" v={data.last.date} />
                  <KV k="Snapshot" v={<a href={data.last.url} target="_blank" rel="noopener noreferrer" className="break-all font-mono text-xs text-accent hover:underline">open ↗</a>} />
                </>
              ) : (
                <p className="text-sm text-fg-faint">—</p>
              )}
            </Card>
          </div>

          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              Snapshot timeline (per year)
            </div>
            <div className="max-h-[28rem] divide-y divide-line-soft/60 overflow-y-auto">
              {data.timeline.map((s) => (
                <a
                  key={s.timestamp}
                  href={s.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="group flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-white/[0.03]"
                >
                  <span className="w-24 shrink-0 font-mono text-fg">{s.date}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted">{s.url}</span>
                  <span className="shrink-0 font-mono text-[11px] text-fg-faint">{s.status || ""}</span>
                  <span className="shrink-0 font-mono text-[10px] text-fg-faint group-hover:text-accent">open ↗</span>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to see its Wayback Machine history and snapshot timeline.
        </p>
      )}
    </div>
  );
}
