"use client";

import { useState } from "react";
import { deepSearch } from "@/lib/api";
import type { DeepSearchResponse } from "@/lib/types";
import ResultsPanel from "../ResultsPanel";
import { Card, KV, RiskMeter, RunBar, ToolError, ToolLoading, useTool } from "./ui";

export default function DeepSearchView() {
  const [target, setTarget] = useState("");
  const [score, setScore] = useState(false);
  const [runId, setRunId] = useState(0);
  const { data, loading, error, run, ran } = useTool<DeepSearchResponse>();

  const enrichment = data?.results.enrichment;

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={target}
        onChange={setTarget}
        onRun={() => {
          setRunId((n) => n + 1);
          run(() => deepSearch(target, score));
        }}
        loading={loading}
        placeholder="acme corp  ·  or  paypal.com"
        button="Deep search"
        hint="Combines platform links, text-clone + phishing dorks, and — for domains — enrichment, lookalikes and clone detection. Domains trigger network-heavy steps and can be slow."
      />

      <label className="-mt-1 flex items-center gap-2 text-sm text-fg-muted">
        <input
          type="checkbox"
          checked={score}
          onChange={(e) => setScore(e.target.checked)}
          className="accent-[var(--color-accent)]"
        />
        Threat scoring on generated links
      </label>

      {loading && <ToolLoading label="Running deep OSINT scan… this can take a while for domains" />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && (
        <div className="animate-fade-in flex flex-col gap-4">
          {enrichment && (
            <>
              <RiskMeter score={enrichment.risk_score ?? 0} />
              <Card title="Enrichment summary">
                <KV k="Domain" v={enrichment.domain} />
                <KV k="Registrar" v={enrichment.whois?.domain_info?.registrar} />
                <KV k="IP" v={enrichment.host?.ip} />
                <KV k="Country" v={enrichment.host?.geolocation?.country} />
                <KV
                  k="Lookalikes"
                  v={String(enrichment.lookalike_domains?.length ?? 0)}
                />
                <KV
                  k="Clone sites"
                  v={String(data.results.clone_sites?.length ?? 0)}
                />
              </Card>
            </>
          )}
          <ResultsPanel key={runId} results={data.links} target={data.target} />
        </div>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          Enter a target (name or domain) to run an extensive combined OSINT scan.
        </p>
      )}
    </div>
  );
}
