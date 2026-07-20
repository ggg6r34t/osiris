"use client";

import { useState } from "react";
import { checkReputation } from "@/lib/api";
import type { ReputationResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

const VERDICT_STYLE: Record<string, string> = {
  listed: "border-danger/40 bg-danger/10 text-danger",
  clean: "border-live/40 bg-live/10 text-live",
  unknown: "border-line bg-surface-2 text-fg-faint",
};

function statusDot(listed: boolean | null) {
  if (listed === true) return <span className="text-danger">● listed</span>;
  if (listed === false) return <span className="text-live">● clean</span>;
  return <span className="text-fg-faint">● n/a</span>;
}

export default function ReputationView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<ReputationResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => checkReputation(target))}
        loading={loading}
        placeholder="evil-domain.com  ·  or  1.2.3.4"
        button="Check"
        hint="Checks the domain/IP against phishing & malware feeds (URLhaus, Spamhaus, SURBL, and Google Safe Browsing if a key is set). Keyless except Safe Browsing."
      />

      {loading && <ToolLoading label="Querying threat feeds…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${VERDICT_STYLE[data.verdict]}`}>
                {data.verdict === "listed" ? `Listed on ${data.listed_count}` : data.verdict}
              </span>
              <span className="font-mono text-sm text-fg">{data.target}</span>
            </div>
            <AddToCase kind="reputation" data={{ [data.is_ip ? "ip" : "domain"]: data.target, verdict: data.verdict }} />
          </div>

          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="divide-y divide-line-soft/60">
              {data.sources.map((s) => (
                <div key={s.source} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                  <span className="w-48 shrink-0 text-fg">{s.source}</span>
                  <span className="w-24 shrink-0 font-mono text-xs">{statusDot(s.listed)}</span>
                  <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">{s.detail || ""}</span>
                  {s.reference && (
                    <a href={s.reference} target="_blank" rel="noopener noreferrer" className="shrink-0 font-mono text-[11px] text-accent hover:underline">
                      ref ↗
                    </a>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain or IP to check it against threat feeds and blocklists.
        </p>
      )}
    </div>
  );
}
