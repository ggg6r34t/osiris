"use client";

import { useState } from "react";
import { enumerateSubdomains } from "@/lib/api";
import type { SubdomainsResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import BatchOpen from "../BatchOpen";
import ExportRows from "./ExportRows";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function SubdomainsView() {
  const [target, setTarget] = useState("");
  const [liveOnly, setLiveOnly] = useState(false);
  const { data, loading, error, run, ran } = useTool<SubdomainsResult>();

  const subs = data?.subdomains ?? [];
  const shown = liveOnly ? subs.filter((s) => s.resolves) : subs;

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => enumerateSubdomains(target))}
        loading={loading}
        placeholder="example.com"
        button="Enumerate"
        hint="Finds subdomains from certificate-transparency logs (crt.sh) and resolves a sample to flag which are live. Keyless."
      />

      {loading && <ToolLoading label="Querying crt.sh and resolving hosts…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && !data.found && (
        <ToolError message={data.error || `No subdomains found for ${data.domain}.`} />
      )}

      {!loading && data && data.found && (
        <div className="animate-fade-in flex flex-col gap-3">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex flex-wrap items-center gap-3">
              <span className="font-mono text-sm text-fg">{data.domain}</span>
              <span className="font-mono text-[11px] text-fg-muted">
                {data.total} subdomains · {data.resolved} live
                {data.total > data.checked ? ` (resolved first ${data.checked})` : ""}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <BatchOpen key={data.domain} urls={subs.filter((s) => s.resolves).map((s) => `http://${s.name}`)} />
              <ExportRows rows={shown} baseName={`subdomains-${data.domain}`} />
              <AddToCase kind="subdomains" data={{ domain: data.domain, total: data.total, resolved: data.resolved }} />
            </div>
          </div>

          <label className="flex items-center gap-2 text-xs text-fg-muted">
            <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} className="accent-[var(--color-accent)]" />
            Live only ({data.resolved})
          </label>

          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="max-h-[32rem] divide-y divide-line-soft/60 overflow-y-auto">
              {shown.map((s) => (
                <div key={s.name} className="flex items-center gap-3 px-4 py-2 text-sm">
                  <span
                    className={`shrink-0 text-xs ${
                      s.resolves === true ? "text-live" : s.resolves === false ? "text-fg-faint" : "text-fg-faint"
                    }`}
                    title={s.resolves === null ? "not resolved (beyond sample)" : s.resolves ? "live" : "does not resolve"}
                  >
                    {s.resolves === true ? "●" : s.resolves === false ? "○" : "·"}
                  </span>
                  <a
                    href={`http://${s.name}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="min-w-0 flex-1 truncate font-mono text-fg transition-colors hover:text-accent"
                  >
                    {s.name}
                  </a>
                  {s.ip && <span className="shrink-0 font-mono text-[11px] text-fg-faint">{s.ip}</span>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to enumerate its subdomains from certificate-transparency logs.
        </p>
      )}
    </div>
  );
}
