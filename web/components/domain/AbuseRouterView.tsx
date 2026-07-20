"use client";

import { useState } from "react";
import { abuseRoute, createTakedown } from "@/lib/api";
import type { AbuseEscalation, AbuseRouteResult } from "@/lib/types";
import AddToCase from "../AddToCase";
import { Card, KV, RunBar, ToolError, ToolLoading, useTool } from "./ui";

function TrackTakedownButton({ data }: { data: AbuseRouteResult }) {
  const [state, setState] = useState<"idle" | "saving" | "done">("idle");
  const bestContact =
    data.registrar.abuse_email ||
    data.hosting.abuse_email ||
    data.email.abuse_email ||
    data.registrar.abuse_form ||
    data.hosting.abuse_form ||
    "";
  return (
    <button
      type="button"
      disabled={state !== "idle"}
      onClick={async () => {
        setState("saving");
        try {
          await createTakedown({ domain: data.domain, contact: bestContact });
          setState("done");
        } catch {
          setState("idle");
        }
      }}
      className="rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 text-xs font-medium text-accent transition-colors hover:bg-accent/20 disabled:opacity-60"
      title="Start tracking this domain's takedown in the Takedowns board"
    >
      {state === "done" ? "Tracking ✓" : state === "saving" ? "Adding…" : "Track takedown"}
    </button>
  );
}

const VERDICT_STYLE: Record<string, string> = {
  live: "border-danger/40 bg-danger/10 text-danger",
  "resolves-no-response": "border-amber-400/40 bg-amber-400/10 text-amber-300",
  "no-a-record": "border-amber-400/40 bg-amber-400/10 text-amber-300",
  parked: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  suspended: "border-live/40 bg-live/10 text-live",
  nxdomain: "border-live/40 bg-live/10 text-live",
  "no-dns-records": "border-live/40 bg-live/10 text-live",
};

function copy(text: string) {
  navigator.clipboard?.writeText(text);
}

function Contact({ email, form }: { email?: string | null; form?: string | null }) {
  if (email && email.includes("@")) {
    return (
      <span className="flex items-center gap-2">
        <a href={`mailto:${email}`} className="font-mono text-fg transition-colors hover:text-accent">
          {email}
        </a>
        <button
          type="button"
          onClick={() => copy(email)}
          className="font-mono text-[10px] text-fg-faint hover:text-accent"
          title="Copy"
        >
          copy
        </button>
      </span>
    );
  }
  if (form) {
    return (
      <a
        href={form}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs text-accent transition-colors hover:bg-accent/20"
      >
        Report form ↗
      </a>
    );
  }
  return <span className="text-fg-faint">— not published</span>;
}

function EscalationRow({ e }: { e: AbuseEscalation }) {
  return (
    <div className="flex items-start gap-3 px-4 py-3">
      <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent/15 font-mono text-xs text-accent">
        {e.order}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-fg">{e.target}</span>
          {e.label && e.label !== e.target && (
            <span className="font-mono text-[11px] text-fg-faint">{e.label}</span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-fg-muted">{e.why}</p>
        <div className="mt-1 text-sm">
          {e.method === "email" ? (
            <Contact email={e.value} />
          ) : e.method === "form" ? (
            <Contact form={e.value} />
          ) : (
            <span className="text-fg-faint">— no public abuse contact (try WHOIS / registry)</span>
          )}
        </div>
      </div>
    </div>
  );
}

export default function AbuseRouterView() {
  const [target, setTarget] = useState("");
  const { data, loading, error, run, ran } = useTool<AbuseRouteResult>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => run(() => abuseRoute(target))}
        loading={loading}
        placeholder="paypal-secure-login.com"
        button="Route"
        hint="Resolves who to report abuse to (registrar, host/CDN, email provider) with email-or-form links, and reads DNS/MX to tell whether the domain/email is still live or taken down. Keyless (RDAP + DNS)."
      />

      {loading && <ToolLoading label="Querying RDAP, DNS, and the host…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          {/* Verdict */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
            <div className="flex items-center gap-3">
              <span
                className={`rounded-lg border px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider ${
                  VERDICT_STYLE[data.verdict.state] ?? "border-line bg-surface-2 text-fg-faint"
                }`}
              >
                {data.verdict.label}
              </span>
              <span className="font-mono text-sm text-fg">{data.domain}</span>
            </div>
            <div className="flex items-center gap-2">
              <TrackTakedownButton data={data} />
              <AddToCase kind="abuse-route" data={{ domain: data.domain, verdict: data.verdict.state }} />
            </div>
          </div>
          {data.verdict.notes.length > 0 && (
            <ul className="-mt-2 flex flex-col gap-1 px-1 text-xs text-fg-muted">
              {data.verdict.notes.map((n, i) => (
                <li key={i}>• {n}</li>
              ))}
            </ul>
          )}

          {/* Escalation path */}
          <Card title="Who to contact — escalation path">
            <div className="-mx-4 -my-4 divide-y divide-line-soft/60">
              {data.escalation.map((e) => (
                <EscalationRow key={e.order} e={e} />
              ))}
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Registrar */}
            <Card title="Registrar & registrant">
              <KV k="Registrar" v={data.registrar.name} />
              <KV k="Abuse" v={<Contact email={data.registrar.abuse_email} form={data.registrar.abuse_form} />} />
              {data.registrar.abuse_phone && <KV k="Abuse phone" v={data.registrar.abuse_phone} />}
              <KV k="IANA ID" v={data.registrar.iana_id} />
              <KV k="Registered" v={data.registrar.registration?.slice(0, 10)} />
              <KV k="Expires" v={data.registrar.expiration?.slice(0, 10)} />
              <KV k="Status" v={data.registrar.status?.join(", ")} />
              <KV k="Registrant" v={data.registrant.name || data.registrant.org || "— redacted"} />
              {data.registrant.email && <KV k="Registrant email" v={data.registrant.email} />}
              {data.registrar.rdap_note && (
                <p className="mt-2 text-xs text-fg-faint">{data.registrar.rdap_note}</p>
              )}
            </Card>

            {/* Hosting */}
            <Card title="Hosting provider">
              <KV k="IP" v={data.hosting.ip} />
              <KV k="Network" v={data.hosting.network} />
              <KV k="ASN" v={data.hosting.asn} />
              <KV
                k="CDN / proxy"
                v={
                  data.hosting.cdn ? (
                    <span className="text-amber-300">{data.hosting.cdn} — real origin hidden; report to the CDN</span>
                  ) : (
                    "none detected"
                  )
                }
              />
              <KV k="Abuse" v={<Contact email={data.hosting.abuse_email} form={data.hosting.abuse_form} />} />
            </Card>

            {/* Email */}
            <Card title="Email service provider">
              <KV
                k="MX"
                v={
                  data.email.has_mx ? (
                    <span className="font-mono text-xs">{data.email.mx_hosts.join(", ")}</span>
                  ) : (
                    <span className="text-amber-300">none configured</span>
                  )
                }
              />
              <KV k="Provider" v={data.email.provider} />
              <KV k="SPF / DMARC" v={`${data.email.spf ? "SPF ✓" : "SPF ✗"} · ${data.email.dmarc ? "DMARC ✓" : "DMARC ✗"}`} />
              <KV k="Abuse" v={<Contact email={data.email.abuse_email} form={data.email.abuse_form} />} />
              <p className="mt-2 rounded-lg border border-line-soft bg-canvas px-3 py-2 text-xs text-fg-muted">
                {data.email.note}
              </p>
            </Card>

            {/* Reporting channels */}
            <Card title="Blocklist & browser reporting">
              <div className="flex flex-col divide-y divide-line-soft/60">
                {data.reporting_channels.map((c) => (
                  <div key={c.name} className="flex items-center justify-between gap-2 py-1.5 text-sm">
                    <span className="text-fg-muted">{c.name}</span>
                    {c.method === "email" ? <Contact email={c.value} /> : <Contact form={c.value} />}
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Pre-filled report */}
          <Card
            title="Pre-filled abuse report"
            right={
              <button
                type="button"
                onClick={() =>
                  copy(`To: ${data.report_email.to}\nSubject: ${data.report_email.subject}\n\n${data.report_email.body}`)
                }
                className="font-mono text-[11px] text-fg-faint hover:text-accent"
              >
                copy
              </button>
            }
          >
            <KV k="To" v={data.report_email.to || "— set an abuse contact above"} />
            <KV k="Subject" v={data.report_email.subject} />
            <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap rounded-lg border border-line-soft bg-canvas px-3 py-2 text-xs text-fg-muted">
              {data.report_email.body}
            </pre>
          </Card>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to find its abuse contacts and check whether it&apos;s still live.
        </p>
      )}
    </div>
  );
}
