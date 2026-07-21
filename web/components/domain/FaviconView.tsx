"use client";

import { useState } from "react";
import { faviconPivot } from "@/lib/api";
import type { FaviconResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import ExportRows from "./ExportRows";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function FaviconView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<FaviconResult>();

  const sh = data?.shodan;

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => faviconPivot(target))}
        loading={loading}
        placeholder="paypa1-login.com"
        button="Hash"
        hint="Computes the Shodan-style favicon hash and finds other hosts serving the same icon (phishing-kit / infra pivot). Hash + Shodan link are keyless; host listing uses SHODAN_API_KEY."
      />

      {loading && <ToolLoading label="Fetching favicon and computing hash…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && !data.found && (
        <ToolError message={data.error || `No favicon found for ${data.domain}.`} />
      )}

      {!loading && data && data.found && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              {data.preview && (
                // eslint-disable-next-line @next/next/no-img-element
                <img src={data.preview} alt="favicon" className="h-8 w-8 rounded border border-line-soft bg-white/5" />
              )}
              <div className="flex flex-col">
                <span className="font-mono text-sm text-fg">{data.domain}</span>
                <span className="font-mono text-[11px] text-fg-faint">hash: {data.hash}</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <a
                href={data.shodan_dork}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent"
              >
                Shodan search ↗
              </a>
              <AddToCase kind="favicon" data={{ domain: data.domain, favicon_hash: data.hash }} />
            </div>
          </div>

          <Card title="Favicon">
            <KV k="Source" v={<a href={data.favicon_url} target="_blank" rel="noopener noreferrer" className="break-all font-mono text-xs text-accent hover:underline">{data.favicon_url}</a>} />
            <KV k="Shodan hash" v={<span className="font-mono">{data.hash}</span>} />
          </Card>

          {sh && !sh.configured && (
            <p className="rounded-lg border border-line-soft bg-canvas px-4 py-2.5 text-xs text-fg-muted">
              Set <span className="font-mono text-fg">SHODAN_API_KEY</span> to list the hosts sharing this favicon here.
              For now, use the Shodan search link above.
            </p>
          )}

          {sh && sh.configured && (
            <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
              <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
                <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                  {sh.total} hosts share this favicon{sh.matches.length < sh.total ? ` (showing ${sh.matches.length})` : ""}
                </span>
                {sh.matches.length > 0 && (
                  <ExportRows rows={sh.matches.map((m) => ({ ...m, hostnames: m.hostnames.join(" ") }))} baseName={`favicon-${data.domain}`} />
                )}
              </div>
              {sh.error ? (
                <p className="px-4 py-6 text-center text-sm text-danger">Shodan error: {sh.error}</p>
              ) : sh.matches.length === 0 ? (
                <p className="px-4 py-6 text-center text-sm text-fg-muted">No other hosts found with this favicon.</p>
              ) : (
                <div className="max-h-[28rem] divide-y divide-line-soft/60 overflow-y-auto">
                  {sh.matches.map((m, i) => (
                    <div key={`${m.ip}:${m.port}:${i}`} className="flex items-center gap-3 px-4 py-2 text-sm">
                      <span className="w-40 shrink-0 font-mono text-fg">{m.ip}:{m.port}</span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted">
                        {m.hostnames.join(", ") || m.org || "—"}
                      </span>
                      {m.country && <span className="shrink-0 font-mono text-[11px] text-fg-faint">{m.country}</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to hash its favicon and pivot to other hosts reusing it.
        </p>
      )}
    </div>
  );
}
