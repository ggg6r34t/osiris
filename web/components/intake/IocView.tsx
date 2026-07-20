"use client";

import { useState } from "react";
import { exportIocs, extractIocs } from "@/lib/api";
import { triggerDownload } from "@/lib/export";
import type { IocExtractResult, IocSet } from "@/lib/types";
import AddToCase from "../AddToCase";
import { ToolError, ToolLoading } from "../domain/ui";

function IocGroup({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded-xl border border-line-soft bg-canvas">
      <div className="flex items-center justify-between border-b border-line-soft px-3 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-wider text-accent">{label}</span>
        <span className="font-mono text-[11px] text-fg-faint">{items.length}</span>
      </div>
      <div className="max-h-52 overflow-y-auto p-2">
        {items.map((v) => (
          <div key={v} className="truncate px-1 py-0.5 font-mono text-xs text-fg">
            {v}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function IocView() {
  const [text, setText] = useState("");
  const [data, setData] = useState<IocExtractResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    try {
      setData(await extractIocs(text));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Extraction failed.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  async function download(format: "stix" | "misp") {
    if (!data) return;
    const doc = await exportIocs({ iocs: data.iocs, format });
    triggerDownload(
      format === "stix" ? "osiris-iocs.stix.json" : "osiris-iocs.misp.json",
      JSON.stringify(doc, null, 2),
      "application/json",
    );
  }

  const iocs: IocSet | undefined = data?.iocs;
  // Domains + IPs are the indicators worth filing as case items.
  const caseIndicators = iocs ? [...iocs.domains, ...iocs.ips] : [];

  return (
    <div className="flex flex-col gap-4">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Paste an alert, report, or email body… defanged IOCs (hxxp, evil[.]com, user[at]host) are refanged automatically."
        rows={7}
        onKeyDown={(e) => {
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run();
        }}
        className="w-full resize-y rounded-lg border border-line bg-canvas px-3 py-2.5 font-mono text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
      />
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={run}
          disabled={loading || !text.trim()}
          className="rounded-lg bg-accent-gradient px-4 py-2 text-sm font-semibold text-white shadow-glow disabled:opacity-40"
        >
          {loading ? "Extracting…" : "Extract IOCs"}
        </button>
        {data && (
          <>
            <span className="font-mono text-xs text-fg-faint">{data.count} indicators</span>
            <div className="ml-auto flex items-center gap-2">
              <button
                type="button"
                onClick={() => download("stix")}
                disabled={data.count === 0}
                className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent disabled:opacity-40"
              >
                Export STIX 2.1
              </button>
              <button
                type="button"
                onClick={() => download("misp")}
                disabled={data.count === 0}
                className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent disabled:opacity-40"
              >
                Export MISP
              </button>
              {caseIndicators.length > 0 && (
                <AddToCase kind="ioc" data={{ indicators: caseIndicators, count: data.count }} />
              )}
            </div>
          </>
        )}
      </div>

      {loading && <ToolLoading label="Refanging and extracting indicators…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && iocs && (
        <div className="animate-fade-in">
          {data!.count === 0 ? (
            <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
              No indicators found in that text.
            </p>
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <IocGroup label="Domains" items={iocs.domains} />
              <IocGroup label="IPs" items={iocs.ips} />
              <IocGroup label="URLs" items={iocs.urls} />
              <IocGroup label="Emails" items={iocs.emails} />
              <IocGroup label="SHA-256" items={iocs.hashes.sha256} />
              <IocGroup label="SHA-1" items={iocs.hashes.sha1} />
              <IocGroup label="MD5" items={iocs.hashes.md5} />
              <IocGroup label="CVEs" items={iocs.cves} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
