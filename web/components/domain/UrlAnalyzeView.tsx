"use client";

import { useState } from "react";
import { analyzeUrl } from "@/lib/api";
import type { UrlAnalysis } from "@/lib/types";
import AddToCase from "../AddToCase";
import ScreenshotButton from "../ScreenshotButton";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

const RISK_STYLE: Record<string, string> = {
  high: "border-danger/40 bg-danger/10 text-danger",
  medium: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  low: "border-live/40 bg-live/10 text-live",
};

export default function UrlAnalyzeView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<UrlAnalysis>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => analyzeUrl(target))}
        loading={loading}
        placeholder="http://paypa1-login.com/verify"
        button="Analyze"
        hint="Fetches the page (HTML only, no JS) and flags credential forms, cross-domain form posts, brand impersonation, redirects and IOCs. It sends one request to the target."
      />

      {loading && <ToolLoading label="Fetching and analyzing the page…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && data.reachable === false && (
        <ToolError message={`Could not fetch the URL (${data.error || "unreachable"}).`} />
      )}

      {!loading && data && data.reachable && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${RISK_STYLE[data.risk || "low"]}`}>
                {data.risk} risk
              </span>
              <span className="font-mono text-sm text-fg">{data.final_domain}</span>
              <span className="font-mono text-[11px] text-fg-faint">HTTP {data.status_code}</span>
            </div>
            <div className="flex items-center gap-2">
              <ScreenshotButton url={data.final_url || data.input} />
              <AddToCase kind="url" data={{ domain: data.final_domain, url: data.final_url, risk: data.risk }} />
            </div>
          </div>

          {data.flags && data.flags.length > 0 && (
            <Card title="Flags">
              <ul className="flex flex-col gap-1.5">
                {data.flags.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <span className={`mt-0.5 shrink-0 rounded border px-1.5 py-px font-mono text-[10px] uppercase ${RISK_STYLE[f.level]}`}>
                      {f.level}
                    </span>
                    <span className="text-fg">{f.text}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Page">
              <KV k="Title" v={data.title} />
              <KV k="Final URL" v={<span className="break-all font-mono text-xs">{data.final_url}</span>} />
              <KV k="Targeted brands" v={data.targeted_brands?.length ? data.targeted_brands.join(", ") : "none detected"} />
              <KV k="Credential forms" v={String(data.credential_forms ?? 0)} />
              <KV k="Meta refresh" v={data.meta_refresh ? "yes" : "no"} />
            </Card>

            <Card title={`Redirect chain (${data.redirect_chain?.length ?? 0})`}>
              <div className="flex flex-col gap-1.5">
                {(data.redirect_chain || []).map((h, i) => (
                  <div key={i} className="flex items-baseline gap-2 text-xs">
                    <span className="shrink-0 font-mono text-fg-faint">{h.status}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-fg-muted">{h.url}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {data.forms && data.forms.length > 0 && (
            <Card title="Forms">
              <div className="flex flex-col divide-y divide-line-soft/60">
                {data.forms.map((f, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2 text-sm">
                    <span className="font-mono text-[11px] uppercase text-fg-faint">{f.method || "get"}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted">{f.action}</span>
                    {f.has_password && <span className="rounded border border-danger/40 bg-danger/10 px-1.5 py-px text-[10px] text-danger">password</span>}
                    {f.cross_domain && <span className="rounded border border-danger/40 bg-danger/10 px-1.5 py-px text-[10px] text-danger">cross-domain</span>}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {data.iocs && (data.iocs.domains.length > 0 || data.iocs.urls.length > 0) && (
            <Card title="Extracted IOCs">
              {data.iocs.urls.length > 0 && <KV k="URLs" v={<span className="font-mono text-xs">{data.iocs.urls.slice(0, 30).join(", ")}</span>} />}
              {data.iocs.domains.length > 0 && <KV k="Domains" v={<span className="font-mono text-xs">{data.iocs.domains.slice(0, 30).join(", ")}</span>} />}
            </Card>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a suspected phishing URL to analyze its page, forms, and redirects.
        </p>
      )}
    </div>
  );
}
