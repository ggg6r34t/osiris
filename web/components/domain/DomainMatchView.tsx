"use client";

import { useState } from "react";
import { domainMatch } from "@/lib/api";
import type { DomainMatch } from "@/lib/types";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function DomainMatchView() {
  const [domain, setDomain] = useState("");
  const { data, loading, error, run, ran } = useTool<DomainMatch[]>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={domain}
        onChange={setDomain}
        onRun={() => run(() => domainMatch(domain))}
        loading={loading}
        placeholder="paypal.com"
        button="Find matches"
        hint="Generates typo variants, then searches certificate-transparency logs for registered lookalikes. Can be slow."
      />

      {loading && <ToolLoading label="Searching certificate logs for lookalike domains…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in overflow-hidden rounded-xl border border-line bg-surface/60">
          <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            {data.length} suspicious {data.length === 1 ? "match" : "matches"}
          </div>
          {data.length === 0 ? (
            <p className="px-4 py-10 text-center text-sm text-fg-muted">
              No suspicious lookalike domains found.
            </p>
          ) : (
            <div className="divide-y divide-line-soft/60">
              {data.map((m, i) => (
                <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5 text-sm">
                  <span className="font-mono text-fg">{m.domain}</span>
                  <span className="text-fg-faint">variant: {m.matched_variant}</span>
                  {m.whois?.domain_info?.registrar && (
                    <span className="text-fg-muted">
                      {m.whois.domain_info.registrar}
                    </span>
                  )}
                  {m.whois?.registration_dates?.creation_date && (
                    <span className="font-mono text-xs text-fg-faint">
                      {m.whois.registration_dates.creation_date}
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
          Enter a domain to detect registered lookalike / typosquatted domains.
        </p>
      )}
    </div>
  );
}
