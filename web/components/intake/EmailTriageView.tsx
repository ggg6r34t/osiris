"use client";

import { useState } from "react";
import { analyzeEmail } from "@/lib/api";
import type { EmailAnalysis } from "@/lib/types";
import AddToCase from "../AddToCase";
import { Card, KV, ToolError, ToolLoading } from "../domain/ui";

const RISK_STYLE: Record<string, string> = {
  high: "border-danger/40 bg-danger/10 text-danger",
  medium: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  low: "border-live/40 bg-live/10 text-live",
};

function authBadge(label: string, val: string | null) {
  const ok = val === "pass";
  const cls = ok
    ? "border-live/40 bg-live/10 text-live"
    : val
      ? "border-danger/40 bg-danger/10 text-danger"
      : "border-line bg-surface text-fg-faint";
  return (
    <span className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase ${cls}`}>
      {label} {val || "absent"}
    </span>
  );
}

export default function EmailTriageView() {
  const [raw, setRaw] = useState("");
  const [data, setData] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(text?: string) {
    const src = (text ?? raw).trim();
    if (!src) return;
    setLoading(true);
    setError(null);
    try {
      setData(await analyzeEmail(src));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Analysis failed.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setRaw(text);
    run(text);
  }

  const iocList = data
    ? [...data.iocs.domains, ...data.iocs.ips, ...data.iocs.urls]
    : [];

  return (
    <div className="flex flex-col gap-4">
      <textarea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        placeholder="Paste the full raw email including headers (or upload a .eml below)…"
        rows={7}
        className="w-full resize-y rounded-lg border border-line bg-canvas px-3 py-2.5 font-mono text-xs text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
      />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => run()}
          disabled={loading || !raw.trim()}
          className="rounded-lg bg-accent-gradient px-4 py-2 text-sm font-semibold text-white shadow-glow disabled:opacity-40"
        >
          {loading ? "Analyzing…" : "Analyze email"}
        </button>
        <label className="cursor-pointer rounded-md border border-line px-3 py-2 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent">
          Upload .eml
          <input type="file" accept=".eml,message/rfc822,text/plain" onChange={onFile} className="hidden" />
        </label>
      </div>

      {loading && <ToolLoading label="Parsing headers, auth results, and IOCs…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${RISK_STYLE[data.risk]}`}>
                {data.risk} risk
              </span>
              {authBadge("SPF", data.auth.spf)}
              {authBadge("DKIM", data.auth.dkim)}
              {authBadge("DMARC", data.auth.dmarc)}
            </div>
            {iocList.length > 0 && (
              <AddToCase kind="email" data={{ from: data.headers.from, subject: data.headers.subject, indicators: iocList, risk: data.risk }} />
            )}
          </div>

          {data.flags.length > 0 && (
            <Card title="Spoofing & authentication flags">
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
            <Card title="Headers">
              <KV k="From" v={data.headers.from} />
              {data.headers.from_name && <KV k="Display name" v={data.headers.from_name} />}
              <KV k="Reply-To" v={data.headers.reply_to} />
              <KV k="Return-Path" v={data.headers.return_path} />
              <KV k="To" v={data.headers.to} />
              <KV k="Subject" v={data.headers.subject} />
              <KV k="Date" v={data.headers.date} />
              <KV k="Origin IP" v={data.origin_ip} />
              {data.headers.x_mailer && <KV k="X-Mailer" v={data.headers.x_mailer} />}
            </Card>

            <Card title={`IOCs (${iocList.length + data.iocs.emails.length})`}>
              {data.iocs.urls.length > 0 && <KV k="URLs" v={<span className="font-mono text-xs">{data.iocs.urls.join(", ")}</span>} />}
              {data.iocs.domains.length > 0 && <KV k="Domains" v={<span className="font-mono text-xs">{data.iocs.domains.join(", ")}</span>} />}
              {data.iocs.ips.length > 0 && <KV k="IPs" v={<span className="font-mono text-xs">{data.iocs.ips.join(", ")}</span>} />}
              {data.iocs.emails.length > 0 && <KV k="Emails" v={<span className="font-mono text-xs">{data.iocs.emails.join(", ")}</span>} />}
              {iocList.length + data.iocs.emails.length === 0 && <p className="text-sm text-fg-faint">None found.</p>}
            </Card>
          </div>

          {data.attachments.length > 0 && (
            <Card title="Attachments">
              <div className="flex flex-col divide-y divide-line-soft/60">
                {data.attachments.map((a, i) => (
                  <div key={i} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2 text-sm">
                    <span className="font-mono text-fg">{a.filename}</span>
                    <span className="text-fg-faint">{a.content_type}</span>
                    <span className="text-fg-faint">{a.size} B</span>
                    {a.sha256 && <span className="font-mono text-[11px] text-fg-faint">sha256:{a.sha256.slice(0, 16)}…</span>}
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card title={`Received chain (${data.received_chain.length} hops)`}>
            <div className="flex flex-col gap-1.5">
              {data.received_chain.map((h, i) => (
                <div key={i} className="text-xs">
                  <span className="font-mono text-fg-muted">{h.raw}</span>
                  {h.ips.length > 0 && (
                    <span className="ml-2 font-mono text-accent">[{h.ips.join(", ")}]</span>
                  )}
                </div>
              ))}
              {data.received_chain.length === 0 && <p className="text-sm text-fg-faint">No Received headers.</p>}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
