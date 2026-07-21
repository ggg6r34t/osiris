"use client";

import { useState } from "react";
import { dnsPosture } from "@/lib/api";
import type { DnsPostureResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

const STATUS_STYLE: Record<string, string> = {
  pass: "border-live/40 bg-live/10 text-live",
  warn: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  fail: "border-danger/40 bg-danger/10 text-danger",
  info: "border-line bg-surface-2 text-fg-faint",
};

const GRADE_STYLE: Record<string, string> = {
  hardened: "border-live/40 bg-live/10 text-live",
  partial: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  spoofable: "border-danger/40 bg-danger/10 text-danger",
};

export default function PostureView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<DnsPostureResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => dnsPosture(target))}
        loading={loading}
        placeholder="example.com"
        button="Check"
        hint="Grades a domain's anti-spoofing / DNS hardening — SPF, DMARC, DKIM, DNSSEC, CAA, MTA-STS, BIMI. Keyless."
      />

      {loading && <ToolLoading label="Checking SPF / DMARC / DKIM / DNSSEC…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${GRADE_STYLE[data.grade]}`}>
                {data.grade}
              </span>
              <span className="font-mono text-sm text-fg">{data.domain}</span>
            </div>
            <AddToCase kind="dns-posture" data={{ domain: data.domain, grade: data.grade, spoofable: data.spoofable }} />
          </div>

          <p className={`rounded-lg border px-4 py-2.5 text-sm ${data.spoofable ? "border-danger/30 bg-danger/10 text-danger" : "border-live/30 bg-live/10 text-live"}`}>
            {data.summary}
          </p>

          <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
            <div className="divide-y divide-line-soft/60">
              {data.checks.map((c) => (
                <div key={c.key} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                  <span className={`mt-0.5 w-14 shrink-0 rounded border px-1.5 py-px text-center font-mono text-[10px] uppercase ${STATUS_STYLE[c.status]}`}>
                    {c.status}
                  </span>
                  <span className="w-24 shrink-0 text-fg">{c.label}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-fg-muted">{c.detail}</div>
                    {c.record && (
                      <div className="mt-0.5 truncate font-mono text-[11px] text-fg-faint" title={c.record}>
                        {c.record}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to grade its email-spoofing and DNS-hardening posture.
        </p>
      )}
    </div>
  );
}
