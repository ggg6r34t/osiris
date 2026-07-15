"use client";

import { useMemo, useState } from "react";
import { brandAbuse } from "@/lib/api";
import type { BrandAbuseResponse, SearchResult } from "@/lib/types";
import CopyButton from "../CopyButton";
import ResultsPanel from "../ResultsPanel";
import { Card, RunBar, ToolError, ToolLoading, useTool } from "./ui";

const EXAMPLE_REGEX = String.raw`.*rr?(i|l){1,}uu?(\.|-?)?hh?(o|0){1,}tt?(e|3){1,}(l|i){1,}.*`;

export default function BrandAbuseView() {
  const [regex, setRegex] = useState("");
  const [idOnly, setIdOnly] = useState(false);
  const [runId, setRunId] = useState(0);
  const { data, loading, error, run, ran } = useTool<BrandAbuseResponse>();

  const links: SearchResult[] = useMemo(
    () =>
      (data?.results ?? [])
        .filter((r) => r.url)
        .map((r) => ({ platform: r.id, category: "brand_abuse", url: r.url as string })),
    [data],
  );
  const idOnlyMatches = useMemo(
    () => (data?.results ?? []).filter((r) => !r.url),
    [data],
  );

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={regex}
        onChange={setRegex}
        onRun={() => {
          setRunId((n) => n + 1);
          run(() => brandAbuse(regex, idOnly));
        }}
        loading={loading}
        placeholder={EXAMPLE_REGEX}
        button="Search"
        hint="Searches the Panda dataset for entries matching this regex (brand abuse / typosquats / violations). Requires VPN + OSIRIS_PANDA_URL/LOGIN/KEY configured on the API."
      />

      <div className="-mt-1 flex items-center justify-between">
        <label className="flex items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            checked={idOnly}
            onChange={(e) => setIdOnly(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          IDs only (faster; no domain extraction)
        </label>
        <button
          type="button"
          onClick={() => setRegex(EXAMPLE_REGEX)}
          className="font-mono text-xs text-fg-faint hover:text-accent"
        >
          use example
        </button>
      </div>

      {loading && <ToolLoading label="Querying Panda for regex matches…" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          <p className="text-sm text-fg-muted">
            <span className="font-mono text-lg font-semibold text-fg">
              {data.count}
            </span>{" "}
            {data.count === 1 ? "match" : "matches"}
            {links.length > 0 && (
              <>
                {" "}
                · <span className="font-mono text-fg">{links.length}</span> with a
                resolvable domain
              </>
            )}
          </p>

          {links.length > 0 && (
            <ResultsPanel key={runId} results={links} target={`regex match`} />
          )}

          {idOnlyMatches.length > 0 && (
            <Card
              title={
                idOnly ? "Matching IDs" : "Matches without a resolvable domain"
              }
              right={
                <CopyButton
                  value={idOnlyMatches.map((r) => r.id).join("\n")}
                  label="Copy IDs"
                  withText
                  className="text-fg-muted"
                />
              }
            >
              <div className="flex max-h-64 flex-wrap gap-1.5 overflow-y-auto">
                {idOnlyMatches.map((r) => (
                  <span
                    key={r.id}
                    className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-xs text-fg-muted"
                  >
                    {r.id}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {data.count === 0 && (
            <p className="rounded-xl border border-line bg-surface/40 px-4 py-10 text-center text-sm text-fg-muted">
              No entries matched this regex.
            </p>
          )}
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a regex to hunt the Panda dataset for brand-abuse / violation
          matches.
        </p>
      )}
    </div>
  );
}
