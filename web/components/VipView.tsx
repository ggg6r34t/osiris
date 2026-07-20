"use client";

import { useState } from "react";
import { assessVip } from "@/lib/api";
import type { RiskLevel, VipPivot, VipScorecard, VipSearchPivot } from "@/lib/types";
import AddToCase from "./AddToCase";
import { ToolError, ToolLoading } from "./domain/ui";
import { exportVipJson, openVipReport } from "@/lib/vipReport";

const LEVEL_STYLE: Record<RiskLevel, string> = {
  high: "border-danger/40 bg-danger/10 text-danger",
  medium: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  low: "border-live/40 bg-live/10 text-live",
  unknown: "border-line bg-surface-2 text-fg-faint",
};

function LevelBadge({ level }: { level: RiskLevel }) {
  return (
    <span
      className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider ${LEVEL_STYLE[level]}`}
    >
      {level}
    </span>
  );
}

function scoreColor(score: number) {
  if (score >= 70) return "var(--color-danger)";
  if (score >= 40) return "#fbbf24";
  return "var(--color-live)";
}

function DimensionCard({
  title,
  level,
  detail,
}: {
  title: string;
  level: RiskLevel;
  detail: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-fg">{title}</span>
        <LevelBadge level={level} />
      </div>
      <div className="text-xs text-fg-muted">{detail}</div>
    </div>
  );
}

function PivotList({ items }: { items: (VipPivot | VipSearchPivot)[] }) {
  if (items.length === 0)
    return <p className="text-xs text-fg-faint">No pivots — add more identifiers.</p>;
  return (
    <div className="flex flex-col divide-y divide-line-soft/60">
      {items.map((p, i) => {
        const label = "label" in p ? p.label : `${p.platform} · ${p.category}`;
        return (
          <a
            key={`${p.url}-${i}`}
            href={p.url}
            target="_blank"
            rel="noopener noreferrer"
            className="group flex items-center gap-2 py-1.5 text-sm text-fg-muted transition-colors hover:text-accent"
          >
            <span className="min-w-0 flex-1 truncate">{label}</span>
            <span className="shrink-0 font-mono text-[10px] text-fg-faint group-hover:text-accent">
              open ↗
            </span>
          </a>
        );
      })}
    </div>
  );
}

function PivotSection({
  title,
  count,
  items,
}: {
  title: string;
  count?: number;
  items: (VipPivot | VipSearchPivot)[];
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-xl border border-line-soft bg-canvas">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-2.5 text-left"
      >
        <span className="text-sm font-medium text-fg">
          {title}{" "}
          <span className="ml-1 font-mono text-[11px] text-fg-faint">
            {count ?? items.length}
          </span>
        </span>
        <span className="text-fg-faint">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="border-t border-line-soft px-4 py-2">
          <PivotList items={items} />
        </div>
      )}
    </div>
  );
}

const EMPTY = {
  name: "",
  aliases: "",
  emails: "",
  usernames: "",
  company: "",
  country: "",
  impersonations: "0",
};

function splitList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  hint,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  hint?: string;
  type?: string;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fg-muted">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25"
      />
      {hint && <span className="text-[11px] text-fg-faint">{hint}</span>}
    </label>
  );
}

export default function VipView() {
  const [form, setForm] = useState(EMPTY);
  const [data, setData] = useState<VipScorecard | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const set = (k: keyof typeof EMPTY) => (v: string) =>
    setForm((f) => ({ ...f, [k]: v }));

  async function run() {
    if (!form.name.trim()) {
      setError("A VIP name is required.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const sc = await assessVip({
        name: form.name.trim(),
        aliases: splitList(form.aliases),
        emails: splitList(form.emails),
        usernames: splitList(form.usernames),
        company: form.company.trim(),
        country: form.country.trim(),
        known_impersonations: Number(form.impersonations) || 0,
      });
      setData(sc);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Assessment failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Input form */}
      <div className="rounded-2xl border border-line bg-surface/60 p-5 shadow-card">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field
            label="Name *"
            value={form.name}
            onChange={set("name")}
            placeholder="Jane Executive"
          />
          <Field
            label="Aliases"
            value={form.aliases}
            onChange={set("aliases")}
            placeholder="J. Exec, Jane E."
            hint="Comma-separated"
          />
          <Field
            label="Emails"
            value={form.emails}
            onChange={set("emails")}
            placeholder="jane@corp.com, jane@gmail.com"
            hint="Comma-separated · used for breach exposure (HIBP)"
          />
          <Field
            label="Usernames / handles"
            value={form.usernames}
            onChange={set("usernames")}
            placeholder="janeexec, jane.e"
            hint="Comma-separated · discover these from social profiles found via the name"
          />
          <Field
            label="Company / org"
            value={form.company}
            onChange={set("company")}
            placeholder="Acme Corp"
          />
          <Field
            label="Country"
            value={form.country}
            onChange={set("country")}
            placeholder="United Kingdom"
          />
          <Field
            label="Confirmed impersonations"
            value={form.impersonations}
            onChange={set("impersonations")}
            type="number"
            hint="Set after reviewing the impersonation hunt, then re-run"
          />
        </div>
        <div className="mt-4 flex items-center gap-3">
          <button
            type="button"
            onClick={run}
            disabled={loading}
            className="rounded-lg bg-accent-gradient px-4 py-2 text-sm font-semibold text-white shadow-glow disabled:opacity-50"
          >
            {loading ? "Assessing…" : "Assess exposure"}
          </button>
          <button
            type="button"
            onClick={() => {
              setForm(EMPTY);
              setData(null);
              setError(null);
            }}
            className="text-xs text-fg-faint hover:text-fg"
          >
            Reset
          </button>
          <p className="ml-auto max-w-md text-right text-[11px] text-fg-faint">
            Defensive exposure assessment — measures risk levels and hands you
            pivots. For authorized executive-protection / DRP use.
          </p>
        </div>
      </div>

      {loading && (
        <ToolLoading label="Resolving profiles, checking breach exposure, building pivots…" />
      )}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          {/* Overall + dimensions */}
          <div className="flex flex-col gap-4 lg:flex-row">
            <div className="flex items-center gap-5 rounded-2xl border border-line bg-surface/60 p-5 shadow-card lg:w-72">
              <div className="flex flex-col">
                <span
                  className="font-mono text-5xl font-semibold tabular-nums leading-none"
                  style={{ color: scoreColor(data.overall_score) }}
                >
                  {data.overall_score}
                </span>
                <span className="mt-1 text-[11px] uppercase tracking-wider text-fg-faint">
                  exposure / 100
                </span>
                <span className="mt-3 font-mono text-sm text-fg">
                  {data.profile.name}
                </span>
                {data.profile.company && (
                  <span className="text-xs text-fg-faint">
                    {data.profile.company}
                  </span>
                )}
              </div>
              <div className="ml-auto flex flex-col items-end gap-1.5">
                <AddToCase kind="vip" data={data as unknown as Record<string, unknown>} />
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    onClick={() => openVipReport(data)}
                    className="rounded-md border border-line px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-fg-muted transition-colors hover:border-accent hover:text-accent"
                    title="Open a print-friendly report (Save as PDF)"
                  >
                    PDF
                  </button>
                  <button
                    type="button"
                    onClick={() => exportVipJson(data)}
                    className="rounded-md border border-line px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-fg-muted transition-colors hover:border-accent hover:text-accent"
                    title="Download the scorecard as JSON"
                  >
                    JSON
                  </button>
                </div>
              </div>
            </div>

            <div className="grid flex-1 grid-cols-1 gap-3 sm:grid-cols-2">
              <DimensionCard
                title="Online presence"
                level={data.levels.presence}
                detail={
                  <span className="flex flex-col gap-0.5">
                    <span>
                      Footprint:{" "}
                      {data.presence.footprint_level === "unknown"
                        ? "no handles supplied"
                        : `${data.presence.resolved_count}/${data.presence.checked_platforms} platforms`}
                    </span>
                    <span>
                      Mentions:{" "}
                      {!data.presence.mention.configured
                        ? "set BRAVE_SEARCH_API_KEY for name-volume"
                        : data.presence.mention.error
                          ? "unavailable"
                          : `${data.presence.mention.level}${
                              data.presence.mention.has_infobox
                                ? " · knowledge panel"
                                : ""
                            }${
                              data.presence.mention.news_results
                                ? ` · ${data.presence.mention.news_results} news`
                                : ""
                            }`}
                    </span>
                  </span>
                }
              />
              <DimensionCard
                title="Service discoverability"
                level={data.levels.discoverability}
                detail={
                  data.discoverability.hibp_configured
                    ? `${data.discoverability.breach_count} breach hits across ${data.discoverability.emails.length} email(s).`
                    : "HIBP not configured — set HAVEIBEENPWNED_API_KEY for breach exposure. Level derived from profile resolution only."
                }
              />
              <DimensionCard
                title="Geo-location risk"
                level={data.levels.geo}
                detail={
                  data.geo.country
                    ? `Coarse tier for ${data.geo.country} — override with judgement + the location pivots.`
                    : "No country supplied."
                }
              />
              <DimensionCard
                title="Impersonations"
                level={data.levels.impersonation}
                detail={`${data.impersonation.confirmed} confirmed. Review the impersonation hunt, then set the count and re-run.`}
              />
            </div>
          </div>

          {/* Resolved profiles */}
          {data.presence.profiles.length > 0 && (
            <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
              <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                {data.presence.profiles.length} resolved profiles
              </div>
              <div className="max-h-72 divide-y divide-line-soft/60 overflow-y-auto">
                {data.presence.profiles.map((p) => (
                  <div
                    key={p.url}
                    className="flex items-center gap-3 px-4 py-2 text-sm"
                  >
                    <span className="w-32 shrink-0 text-fg-muted">{p.platform}</span>
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="min-w-0 flex-1 truncate font-mono text-fg transition-colors hover:text-accent"
                    >
                      {p.url}
                    </a>
                    <span className="shrink-0 font-mono text-[11px] text-fg-faint">
                      @{p.username}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Breach detail */}
          {data.discoverability.hibp_configured &&
            data.discoverability.emails.some((e) => e.count > 0) && (
              <div className="rounded-2xl border border-line bg-surface/60 p-4 shadow-card">
                <div className="mb-2 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
                  Breach exposure
                </div>
                <div className="flex flex-col gap-2">
                  {data.discoverability.emails
                    .filter((e) => e.count > 0)
                    .map((e) => (
                      <div key={e.email} className="text-sm">
                        <span className="font-mono text-fg">{e.email}</span>
                        <span className="ml-2 text-danger">{e.count} breaches</span>
                        <span className="ml-2 text-xs text-fg-faint">
                          {e.breaches.slice(0, 12).join(", ")}
                          {e.breaches.length > 12 ? " …" : ""}
                        </span>
                      </div>
                    ))}
                </div>
              </div>
            )}

          {/* Pivots */}
          <div className="flex flex-col gap-2">
            <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              Investigator pivots
            </span>
            <PivotSection
              title="Presence & handle discovery"
              items={data.pivots.social}
            />
            <PivotSection
              title="Impersonation hunt"
              items={data.pivots.social}
            />
            <PivotSection title="Family / relatives" items={data.pivots.family} />
            <PivotSection title="Business / associates" items={data.pivots.business} />
            <PivotSection title="Geo / location" items={data.pivots.geo} />
          </div>
        </div>
      )}

      {!loading && !data && !error && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-12 text-center text-sm text-fg-muted">
          Enter a VIP and run an exposure assessment. Start with the name; add
          emails and any handles you discover for a fuller picture.
        </p>
      )}
    </div>
  );
}
