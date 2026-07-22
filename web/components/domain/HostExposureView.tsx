"use client";

import { useState } from "react";
import { shodanHost } from "@/lib/api";
import type { ShodanHostResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import ExportRows from "./ExportRows";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function HostExposureView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<ShodanHostResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => shodanHost(target))}
        loading={loading}
        placeholder="example.com  ·  or  1.2.3.4"
        button="Scan"
        hint="Resolves the host and shows its Shodan exposure — open ports, detected services/versions, banners and known CVEs. Requires SHODAN_API_KEY."
      />

      {loading && <ToolLoading label="Querying Shodan…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && !data.configured && (
        <div className="rounded-xl border border-line bg-surface/40 px-4 py-8 text-center text-sm text-fg-muted">
          Shodan isn&apos;t configured. Set <span className="font-mono text-fg">SHODAN_API_KEY</span> in <code>.env</code> to use host exposure.
        </div>
      )}

      {!loading && data && data.configured && !data.found && (
        <ToolError message={data.error || `No Shodan data for ${data.domain}.`} />
      )}

      {!loading && data && data.found && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span className="font-mono text-sm text-fg">{data.domain}</span>
              <span className="font-mono text-[11px] text-fg-faint">
                {data.ip} · {(data.ports || []).length} open port{(data.ports || []).length === 1 ? "" : "s"}
                {data.vulns && data.vulns.length > 0 ? ` · ${data.vulns.length} CVEs` : ""}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <a href={data.shodan_url} target="_blank" rel="noopener noreferrer" className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent">
                Shodan host ↗
              </a>
              <AddToCase kind="shodan-host" data={{ domain: data.domain, ip: data.ip, ports: data.ports }} />
            </div>
          </div>

          <Card title="Host">
            <KV k="IP" v={data.ip} />
            <KV k="Org" v={data.org} />
            <KV k="ISP" v={data.isp} />
            <KV k="ASN" v={data.asn} />
            <KV k="OS" v={data.os} />
            <KV k="Country" v={data.country} />
            <KV k="Hostnames" v={(data.hostnames || []).join(", ")} />
            <KV k="Last update" v={data.last_update?.slice(0, 10)} />
          </Card>

          {data.vulns && data.vulns.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {data.vulns.map((c) => (
                <a
                  key={c}
                  href={`https://nvd.nist.gov/vuln/detail/${c}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded-md border border-danger/40 bg-danger/10 px-2 py-0.5 font-mono text-xs text-danger hover:underline"
                >
                  {c}
                </a>
              ))}
            </div>
          )}

          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
              <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                {(data.services || []).length} services
              </span>
              {(data.services || []).length > 0 && (
                <ExportRows rows={data.services as unknown as Record<string, unknown>[]} baseName={`shodan-${data.ip}`} />
              )}
            </div>
            <div className="max-h-[28rem] divide-y divide-line-soft/60 overflow-y-auto">
              {(data.services || []).map((s, i) => (
                <div key={`${s.port}-${i}`} className="px-4 py-2 text-sm">
                  <div className="flex items-center gap-3">
                    <span className="w-20 shrink-0 font-mono text-fg">{s.port}/{s.transport}</span>
                    <span className="min-w-0 flex-1 truncate text-fg-muted">
                      {[s.product, s.version].filter(Boolean).join(" ") || "—"}
                    </span>
                  </div>
                  {s.banner && (
                    <pre className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap rounded bg-canvas px-2 py-1 font-mono text-[11px] text-fg-faint">
                      {s.banner}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain or IP to see its Shodan host exposure (open ports, services, CVEs).
        </p>
      )}
    </div>
  );
}
