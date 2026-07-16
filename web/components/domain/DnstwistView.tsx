"use client";

import { useMemo, useState } from "react";
import { dnstwist } from "@/lib/api";
import type { DnstwistEntry } from "@/lib/types";
import ExportRows from "./ExportRows";
import AddToCase from "../AddToCase";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function DnstwistView() {
  const [domain, setDomain] = useState("");
  const [showAll, setShowAll] = useState(false);
  const { data, loading, error, run, ran } = useTool<DnstwistEntry[]>();

  const registered = useMemo(
    () => (data ?? []).filter((e) => e.dns_a && e.dns_a.length > 0),
    [data],
  );
  const rows = showAll ? (data ?? []) : registered;

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={domain}
        onChange={setDomain}
        onRun={() => {
          setShowAll(false);
          run(() => dnstwist(domain));
        }}
        loading={loading}
        placeholder="google.com"
        button="Run dnstwist"
        hint="Runs the dnstwist permutation engine. It generates thousands of variants and resolves DNS — this can take a minute or more."
      />

      {loading && <ToolLoading label="Running dnstwist permutation scan…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line-soft px-4 py-2.5">
            <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              {registered.length} registered · {data.length} permutations
            </span>
            <div className="flex items-center gap-2">
              <ExportRows
                rows={rows.map((e) => ({
                  domain: e.domain,
                  fuzzer: e.fuzzer ?? "",
                  dns_a: (e.dns_a ?? []).join(" "),
                }))}
                baseName={`dnstwist-${domain}`}
              />
              <button
                type="button"
                onClick={() => setShowAll((v) => !v)}
                className="text-xs text-fg-faint hover:text-accent"
              >
                {showAll ? "Show registered only" : "Show all permutations"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowAll(false);
                  run(() => dnstwist(domain, true));
                }}
                className="rounded-md border border-line bg-surface px-2.5 py-1 text-xs font-medium text-fg-muted hover:text-fg"
              >
                ↻ Refresh
              </button>
            </div>
          </div>
          {rows.length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-fg-muted">
              No {showAll ? "" : "registered "}permutations found.
            </p>
          ) : (
            <div className="max-h-[32rem] divide-y divide-line-soft/60 overflow-y-auto">
              {rows.map((e, i) => (
                <div key={i} className="group flex items-center gap-3 px-4 py-2 text-sm">
                  <span className="w-56 shrink-0 truncate font-mono text-fg" title={e.domain}>
                    {e.domain}
                  </span>
                  <span className="w-24 shrink-0 font-mono text-[11px] text-fg-faint">
                    {e.fuzzer}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted">
                    {e.dns_a?.join(", ") || "—"}
                  </span>
                  {e.dns_a && e.dns_a.length > 0 && (
                    <span className="shrink-0 opacity-0 transition-opacity group-hover:opacity-100">
                      <AddToCase
                        compact
                        kind="domain"
                        data={{ domain: e.domain, dns_a: e.dns_a.join(" ") }}
                      />
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to run a dnstwist permutation scan.
        </p>
      )}
    </div>
  );
}
