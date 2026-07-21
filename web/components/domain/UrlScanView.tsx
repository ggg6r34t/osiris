"use client";

import { useState } from "react";
import { urlscanScan } from "@/lib/api";
import type { UrlScanResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import { Card, KV, ToolError, ToolLoading, useTool } from "./ui";

const VISIBILITIES = ["unlisted", "private", "public"] as const;

function List({ label, items }: { label: string; items: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <div>
      <div className="mb-1 font-mono text-[11px] uppercase tracking-wider text-fg-faint">
        {label} ({items.length})
      </div>
      <div className="max-h-40 overflow-y-auto rounded-lg border border-line-soft bg-canvas p-2">
        {items.map((v) => (
          <div key={v} className="truncate px-1 py-0.5 font-mono text-xs text-fg">
            {v}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function UrlScanView() {
  const [target, setTarget] = useState("");
  const [visibility, setVisibility] = useState<string>("unlisted");
  const { data, loading, error, run, ran } = useTool<UrlScanResult>();

  const v = data?.verdict;
  const p = data?.page;
  const infra = data?.infrastructure;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run(() => urlscanScan(target, visibility))}
          placeholder="http://paypa1-login.com/verify"
          className="flex-1 rounded-lg border border-line bg-canvas px-3 py-2.5 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
        />
        <select
          value={visibility}
          onChange={(e) => setVisibility(e.target.value)}
          className="rounded-lg border border-line bg-canvas px-3 py-2.5 text-sm text-fg outline-none focus:border-accent/70"
          title="Scan visibility on urlscan.io"
        >
          {VISIBILITIES.map((x) => (
            <option key={x} value={x} className="bg-surface-2">
              {x}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => run(() => urlscanScan(target, visibility))}
          disabled={loading || !target.trim()}
          className="rounded-lg bg-accent-gradient px-5 py-2.5 text-sm font-semibold text-white shadow-glow disabled:opacity-40"
        >
          {loading ? "Scanning…" : "Scan"}
        </button>
      </div>
      <p className="-mt-1 text-xs text-fg-faint">
        Submits the URL to urlscan.io for a sandboxed browser render (from their infra, not yours). Default
        <span className="text-fg"> unlisted</span> keeps it out of urlscan&apos;s public search. Requires URLSCAN_API_KEY.
      </p>

      {loading && <ToolLoading label="Submitting to urlscan.io and waiting for the render (~20–40s)…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data?.pending && (
        <div className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-4 py-3 text-sm text-amber-300">
          Scan submitted but not ready yet.{" "}
          <a href={data.result_url} target="_blank" rel="noopener noreferrer" className="underline">
            Open the result on urlscan.io ↗
          </a>
        </div>
      )}

      {!loading && data && !data.pending && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${
                  v?.malicious
                    ? "border-danger/40 bg-danger/10 text-danger"
                    : "border-live/40 bg-live/10 text-live"
                }`}
              >
                {v?.malicious ? "Malicious" : "Not flagged"} · score {v?.score ?? 0}
              </span>
              {p?.domain && <span className="font-mono text-sm text-fg">{p.domain}</span>}
              {data.visibility && (
                <span className="rounded border border-line px-1.5 py-px font-mono text-[10px] text-fg-faint">
                  {data.visibility}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <a
                href={data.result_url}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent"
              >
                urlscan report ↗
              </a>
              <AddToCase kind="urlscan" data={{ domain: p?.domain, url: p?.url, malicious: v?.malicious, score: v?.score }} />
            </div>
          </div>

          {v && (v.brands.length > 0 || v.categories.length > 0) && (
            <div className="flex flex-wrap gap-2">
              {v.brands.map((b) => (
                <span key={b} className="rounded-md border border-danger/40 bg-danger/10 px-2 py-0.5 text-xs text-danger">
                  brand: {b}
                </span>
              ))}
              {v.categories.map((c) => (
                <span key={c} className="rounded-md border border-line bg-surface-2 px-2 py-0.5 text-xs text-fg-muted">
                  {c}
                </span>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {data.screenshot && (
              <Card title="Screenshot">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={data.screenshot}
                  alt="urlscan.io page screenshot"
                  className="w-full rounded-lg border border-line-soft"
                  loading="lazy"
                />
              </Card>
            )}
            <Card title="Page">
              <KV k="Title" v={p?.title} />
              <KV k="Final URL" v={<span className="break-all font-mono text-xs">{p?.url}</span>} />
              <KV k="IP" v={p?.ip} />
              <KV k="Server" v={p?.server} />
              <KV k="ASN" v={p?.asn ? `${p.asn} ${p.asnname ?? ""}` : null} />
              <KV k="Country" v={p?.country} />
              <KV k="TLS issuer" v={p?.tls_issuer} />
            </Card>
          </div>

          {infra && (
            <Card title="Contacted infrastructure">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <List label="IPs" items={infra.ips} />
                <List label="Domains" items={infra.domains} />
                <List label="ASNs" items={infra.asns} />
                <List label="Servers" items={infra.servers} />
              </div>
            </Card>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a URL to scan it on urlscan.io — screenshot, verdict, targeted brands, and contacted infrastructure.
        </p>
      )}
    </div>
  );
}
