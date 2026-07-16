"use client";

import { useState } from "react";
import { enrichBulk, enrichDomain, takedown } from "@/lib/api";
import { triggerDownload } from "@/lib/export";
import type { BulkEnrichResponse, EnrichResult, TakedownEmail } from "@/lib/types";
import CopyButton from "../CopyButton";
import { DownloadIcon } from "../icons";
import ExportRows from "./ExportRows";
import { Card, KV, RiskMeter, RunBar, ToolError, ToolLoading, useTool } from "./ui";

function Indicators({ flags }: { flags?: Record<string, boolean> }) {
  const entries = Object.entries(flags ?? {});
  if (entries.length === 0) return <span className="text-fg-faint">—</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([k, on]) => (
        <span
          key={k}
          className={`rounded border px-1.5 py-px font-mono text-[10px] ${
            on
              ? "border-danger/40 bg-danger/10 text-danger"
              : "border-line bg-surface text-fg-faint"
          }`}
        >
          {k.replace(/_/g, " ")}
        </span>
      ))}
    </div>
  );
}

function TakedownPanel({ enrichment }: { enrichment: EnrichResult }) {
  const [brand, setBrand] = useState("");
  const [reporter, setReporter] = useState("");
  const [mail, setMail] = useState<TakedownEmail | null>(null);
  const [loading, setLoading] = useState(false);

  async function generate() {
    setLoading(true);
    try {
      setMail(await takedown(enrichment, brand, reporter));
    } catch {
      /* keep panel usable */
    } finally {
      setLoading(false);
    }
  }

  const field =
    "rounded-md border border-line bg-canvas px-2.5 py-1.5 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25";

  return (
    <Card title="Takedown / abuse report">
      <div className="flex flex-col gap-3">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <input className={field} value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="Brand (e.g. PayPal)" />
          <input className={field} value={reporter} onChange={(e) => setReporter(e.target.value)} placeholder="Reporter (you / team)" />
        </div>
        <button
          type="button"
          onClick={generate}
          disabled={loading}
          className="self-start rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-sm font-medium text-accent transition-colors hover:bg-accent/20 disabled:opacity-40"
        >
          {loading ? "Generating…" : "Generate abuse email"}
        </button>

        {mail && (
          <div className="flex flex-col gap-2">
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              To
              <input className={field} value={mail.to} onChange={(e) => setMail({ ...mail, to: e.target.value })} placeholder="abuse contact not resolved — add manually" />
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Subject
              <input className={field} value={mail.subject} onChange={(e) => setMail({ ...mail, subject: e.target.value })} />
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Body
              <textarea rows={9} className={`${field} resize-y font-mono text-xs`} value={mail.body} onChange={(e) => setMail({ ...mail, body: e.target.value })} />
            </label>
            <div className="flex items-center gap-3">
              <CopyButton value={`${mail.subject}\n\n${mail.body}`} label="Copy email" withText className="rounded-md border border-line bg-surface px-3 py-1.5" />
              <button
                type="button"
                onClick={() =>
                  triggerDownload(
                    `takedown-${enrichment.domain || "report"}.eml`,
                    `To: ${mail.to}\nSubject: ${mail.subject}\n\n${mail.body}\n`,
                    "message/rfc822",
                  )
                }
                className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
              >
                <DownloadIcon className="h-4 w-4" /> .eml
              </button>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

function EnrichResultView({
  data,
  onRefresh,
  refreshing,
}: {
  data: EnrichResult;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  const dns = data.dns ?? {};
  const dnsList = (key: string): string =>
    ([] as string[]).concat((dns[key] as string[] | string) ?? []).join(", ");
  const lookalikeRows = (data.lookalike_domains ?? []).map((m) => ({
    domain: m.domain,
    matched_variant: m.matched_variant,
  }));

  return (
    <div className="animate-fade-in flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-sm text-fg-muted">{data.domain}</span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            disabled={refreshing}
            className="rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:text-fg disabled:opacity-40"
          >
            {refreshing ? "Refreshing…" : "↻ Refresh"}
          </button>
          <button
            type="button"
            onClick={() =>
              triggerDownload(
                `enrich-${data.domain}.json`,
                JSON.stringify(data, null, 2),
                "application/json",
              )
            }
            className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:text-fg"
          >
            <DownloadIcon className="h-4 w-4" /> JSON
          </button>
        </div>
      </div>

      <RiskMeter score={data.risk_score ?? 0} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="WHOIS">
          {data.whois?.error ? (
            <p className="text-sm text-fg-faint">{data.whois.error}</p>
          ) : (
            <>
              <KV k="Registrar" v={data.whois?.domain_info?.registrar} />
              <KV k="TLD" v={data.whois?.domain_info?.tld} />
              <KV k="Created" v={data.whois?.registration_dates?.creation_date} />
              <KV k="Expires" v={data.whois?.registration_dates?.expiration_date} />
              <KV k="Age (days)" v={data.whois?.registration_dates?.domain_age_days} />
              <KV k="Emails" v={(data.whois?.contacts?.emails ?? []).join(", ")} />
              <KV k="Indicators" v={<Indicators flags={data.whois?.scam_indicators} />} />
            </>
          )}
        </Card>

        <Card title="Hosting">
          {data.host?.host_error ? (
            <p className="text-sm text-fg-faint">{data.host.host_error}</p>
          ) : (
            <>
              <KV k="IP" v={data.host?.ip} />
              <KV k="ASN" v={data.host?.asn} />
              <KV k="Network" v={data.host?.hosted_by} />
              <KV k="Country" v={data.host?.geolocation?.country} />
              <KV k="ISP" v={data.host?.geolocation?.isp} />
              <KV k="Abuse" v={data.host?.abuse_contact?.email} />
            </>
          )}
        </Card>

        <Card title="DNS">
          <KV k="A" v={dnsList("A")} />
          <KV k="MX" v={dnsList("MX")} />
          <KV k="NS" v={dnsList("NS")} />
          <KV k="TXT" v={dnsList("TXT")} />
        </Card>

        <Card title="SSL Certificate">
          {data.ssl_certificate?.error ? (
            <p className="text-sm text-fg-faint">{data.ssl_certificate.error}</p>
          ) : (
            <>
              <KV k="Issuer" v={data.ssl_certificate?.issuer?.CN} />
              <KV k="Valid to" v={data.ssl_certificate?.valid_to} />
              <KV k="Self-signed" v={String(data.ssl_certificate?.is_self_signed ?? "—")} />
              <KV k="Low-trust CA" v={String(data.ssl_certificate?.low_trust_ca ?? "—")} />
            </>
          )}
        </Card>

        <Card title="Page / Favicon">
          <KV k="Title" v={data.page_metadata?.title} />
          <KV
            k="Phishing words"
            v={
              data.page_metadata?.phishing_keywords_found ? (
                <span className="text-danger">detected</span>
              ) : (
                "none"
              )
            }
          />
          <KV k="Favicon MD5" v={data.favicon?.favicon_hash_md5} />
          <KV k="Content hash" v={data.content_hash} />
        </Card>

        <Card
          title="Lookalike domains"
          right={
            <div className="flex items-center gap-2">
              <ExportRows rows={lookalikeRows} baseName={`lookalikes-${data.domain}`} />
              <span className="font-mono text-xs text-fg-faint">
                {lookalikeRows.length}
              </span>
            </div>
          }
        >
          {lookalikeRows.length > 0 ? (
            <div className="flex max-h-56 flex-col gap-1 overflow-y-auto">
              {lookalikeRows.map((m, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <span className="font-mono text-fg">{m.domain}</span>
                  <span className="text-fg-faint">← {m.matched_variant}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-fg-faint">None found.</p>
          )}
        </Card>
      </div>

      <TakedownPanel enrichment={data} />
    </div>
  );
}

function BulkEnrich() {
  const [text, setText] = useState("");
  const { data, loading, error, run, ran } = useTool<BulkEnrichResponse>();
  const rows = (data?.results ?? []) as unknown as Record<string, unknown>[];

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={text}
        onChange={setText}
        onRun={() =>
          run(() =>
            enrichBulk(
              text.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
            ),
          )
        }
        loading={loading}
        multiline
        placeholder={"paypal.com\nstripe.com\nexample.com"}
        button="Enrich all"
        hint="Enrich up to 25 domains at once (risk score + key facts). ⌘/Ctrl+Enter to run."
      />

      {loading && <ToolLoading label="Enriching domains in parallel…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && data.results.length > 0 && (
        <div className="animate-fade-in overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
          <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
            <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              {data.results.length} domains
            </span>
            <ExportRows rows={rows} baseName="enrich-bulk" />
          </div>
          <div className="divide-y divide-line-soft/60">
            {data.results.map((r) => (
              <div key={r.domain} className="flex items-center gap-3 px-4 py-2 text-sm">
                <span className="w-52 shrink-0 truncate font-mono text-fg">{r.domain}</span>
                {r.error ? (
                  <span className="text-danger">{r.error}</span>
                ) : (
                  <>
                    <span className="w-16 shrink-0 font-mono tabular-nums">
                      {r.risk_score ?? "—"}
                    </span>
                    <span className="w-40 shrink-0 truncate text-fg-muted">{r.registrar ?? "—"}</span>
                    <span className="w-28 shrink-0 font-mono text-fg-muted">{r.ip ?? "—"}</span>
                    <span className="shrink-0 text-fg-muted">{r.country ?? "—"}</span>
                    <span className="ml-auto font-mono text-xs text-fg-faint">
                      {r.lookalikes ?? 0} lookalikes
                    </span>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Paste multiple domains (one per line) to enrich them in bulk.
        </p>
      )}
    </div>
  );
}

export default function EnrichView() {
  const [mode, setMode] = useState<"single" | "bulk">("single");
  const [domain, setDomain] = useState("");
  const { data, loading, error, run, ran } = useTool<EnrichResult>();

  return (
    <div className="flex flex-col gap-4">
      <div className="flex rounded-lg border border-line bg-canvas p-0.5 text-sm">
        {(["single", "bulk"] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            className={`rounded-md px-3 py-1 font-medium capitalize transition-colors ${
              mode === m ? "bg-accent/15 text-accent" : "text-fg-muted hover:text-fg"
            }`}
          >
            {m}
          </button>
        ))}
      </div>

      {mode === "bulk" ? (
        <BulkEnrich />
      ) : (
        <>
          <RunBar
            value={domain}
            onChange={setDomain}
            onRun={() => run(() => enrichDomain(domain))}
            loading={loading}
            placeholder="paypal.com"
            button="Enrich"
            hint="WHOIS, DNS, hosting/ASN, SSL, favicon hash, threat intel and a computed risk score."
          />

          {loading && <ToolLoading label="Enriching domain… (WHOIS, DNS, SSL, threat intel)" />}
          {!loading && error && <ToolError message={error} />}

          {!loading && data && (
            <EnrichResultView
              data={data}
              refreshing={loading}
              onRefresh={() => run(() => enrichDomain(domain, true))}
            />
          )}

          {!loading && !ran && (
            <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
              Enter a domain to enrich it with WHOIS, DNS, hosting, SSL and threat
              intelligence.
            </p>
          )}
        </>
      )}
    </div>
  );
}
