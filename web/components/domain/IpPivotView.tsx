"use client";

import { useState } from "react";
import { ipPivot } from "@/lib/api";
import type { IpPivotResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import ScreenshotButton from "../ScreenshotButton";
import ExportRows from "./ExportRows";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function IpPivotView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<IpPivotResult>();
  const domains = data?.domains ?? [];

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => ipPivot(target))}
        loading={loading}
        placeholder="paypal.com  ·  or  1.2.3.4"
        button="Pivot"
        hint="Resolves the host IP and lists other domains sharing it (reverse-IP) — useful for finding shared phishing infrastructure. Reverse-IP data is rate-limited."
      />

      {loading && <ToolLoading label="Resolving host and looking up co-hosted domains…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          <Card title="Host">
            {data.error ? (
              <p className="text-sm text-fg-faint">{data.error}</p>
            ) : (
              <>
                <KV k="IP" v={data.ip} />
                <KV k="ASN" v={data.asn} />
                <KV k="Network" v={data.network} />
                <KV k="Country" v={data.country} />
                <KV k="Co-hosted" v={`${data.domain_count ?? 0} domains`} />
              </>
            )}
          </Card>

          {domains.length > 0 && (
            <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
              <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
                <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                  {domains.length} domains on {data.ip}
                </span>
                <ExportRows
                  rows={domains.map((d) => ({ domain: d, ip: data.ip }))}
                  baseName={`reverse-ip-${data.ip}`}
                />
              </div>
              <div className="max-h-[32rem] divide-y divide-line-soft/60 overflow-y-auto">
                {domains.map((d) => (
                  <div key={d} className="group flex items-center gap-3 px-4 py-2 text-sm">
                    <a
                      href={`http://${d}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="min-w-0 flex-1 truncate font-mono text-fg transition-colors hover:text-accent"
                    >
                      {d}
                    </a>
                    <span className="flex items-center gap-2">
                      <AddToCase compact kind="domain" data={{ domain: d, ip: data.ip }} />
                      <span className="opacity-0 transition-opacity group-hover:opacity-100">
                        <ScreenshotButton url={`http://${d}`} />
                      </span>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain or IP to pivot on its host and find co-hosted domains.
        </p>
      )}
    </div>
  );
}
