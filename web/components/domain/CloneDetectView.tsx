"use client";

import { useState } from "react";
import { cloneDetect } from "@/lib/api";
import type { CloneDetectResult } from "@/lib/types";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function CloneDetectView() {
  const [domain, setDomain] = useState("");
  const { data, loading, error, run, ran } = useTool<CloneDetectResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={domain}
        onChange={setDomain}
        onRun={() => run(() => cloneDetect(domain))}
        loading={loading}
        placeholder="paypal.com"
        button="Detect clones"
        hint="Hashes the original site, then compares typo-variant sites that are live for a byte-identical clone."
      />

      {loading && <ToolLoading label="Hashing original and comparing live typo variants…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in overflow-hidden rounded-xl border border-line bg-surface/60">
          <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            {data.clones.length} clone{data.clones.length === 1 ? "" : "s"} ·{" "}
            {data.variants_checked} variants checked
          </div>
          {data.clones.length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-fg-muted">
              No byte-identical clones detected among live typo variants.
            </p>
          ) : (
            <div className="divide-y divide-line-soft/60">
              {data.clones.map((c) => (
                <div key={c} className="flex items-center gap-2 px-4 py-2.5 text-sm">
                  <span className="h-2 w-2 shrink-0 rounded-full bg-danger" />
                  <a
                    href={`http://${c}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-fg transition-colors hover:text-accent"
                  >
                    {c}
                  </a>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to detect cloned copies among typosquatted variants.
        </p>
      )}
    </div>
  );
}
