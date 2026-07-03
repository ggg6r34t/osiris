"use client";

import { useState } from "react";
import { enrichDomain } from "@/lib/api";
import type { EnrichResult } from "@/lib/types";
import { Card, KV, RiskMeter, RunBar, ToolError, ToolLoading, useTool } from "./ui";

function Indicators({ flags }: { flags?: Record<string, boolean> }) {
  if (!flags) return <span className="text-fg-faint">—</span>;
  const entries = Object.entries(flags);
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

export default function EnrichView() {
  const [domain, setDomain] = useState("");
  const { data, loading, error, run, ran } = useTool<EnrichResult>();

  const dns = data?.dns ?? {};
  const dnsList = (key: string): string =>
    ([] as string[]).concat((dns[key] as string[] | string) ?? []).join(", ");

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={domain}
        onChange={setDomain}
        onRun={() => run(() => enrichDomain(domain))}
        loading={loading}
        placeholder="paypal.com"
        button="Enrich"
        hint="WHOIS, DNS, hosting/ASN, SSL, favicon hash, threat intel and a computed risk score. Can take 30–60s."
      />

      {loading && <ToolLoading label="Enriching domain… (WHOIS, DNS, SSL, threat intel)" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
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
                  <KV
                    k="Self-signed"
                    v={String(data.ssl_certificate?.is_self_signed ?? "—")}
                  />
                  <KV
                    k="Low-trust CA"
                    v={String(data.ssl_certificate?.low_trust_ca ?? "—")}
                  />
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
                <span className="font-mono text-xs text-fg-faint">
                  {data.lookalike_domains?.length ?? 0}
                </span>
              }
            >
              {data.lookalike_domains && data.lookalike_domains.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {data.lookalike_domains.slice(0, 12).map((m, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm">
                      <span className="font-mono text-fg">{m.domain}</span>
                      <span className="text-fg-faint">
                        ← {m.matched_variant}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-fg-faint">None found.</p>
              )}
            </Card>
          </div>
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a domain to enrich it with WHOIS, DNS, hosting, SSL and threat
          intelligence.
        </p>
      )}
    </div>
  );
}
