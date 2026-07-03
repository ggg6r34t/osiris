"use client";

import { useState } from "react";
import { phishingDorks, textClone } from "@/lib/api";
import type { SearchResult } from "@/lib/types";
import ResultsPanel from "../ResultsPanel";
import { RunBar, ToolError, ToolLoading, useTool } from "./ui";

function LinkToolBase({
  placeholder,
  hint,
  button,
  multiline,
  runner,
  emptyPrompt,
  loadingLabel,
}: {
  placeholder: string;
  hint: string;
  button: string;
  multiline: boolean;
  runner: (value: string) => Promise<SearchResult[]>;
  emptyPrompt: string;
  loadingLabel: string;
}) {
  const [value, setValue] = useState("");
  const [runId, setRunId] = useState(0);
  const { data, loading, error, run, ran } = useTool<SearchResult[]>();

  return (
    <div className="flex flex-col gap-4">
      <RunBar
        value={value}
        onChange={setValue}
        onRun={() => {
          setRunId((n) => n + 1);
          run(() => runner(value));
        }}
        loading={loading}
        placeholder={placeholder}
        button={button}
        multiline={multiline}
        hint={hint}
      />

      {loading && <ToolLoading label={loadingLabel} />}
      {!loading && error && <ToolError message={error} />}

      {!loading && data && data.length > 0 && (
        <ResultsPanel key={runId} results={data} target={value.trim()} />
      )}
      {!loading && data && data.length === 0 && (
        <p className="rounded-xl border border-line bg-surface/40 px-4 py-10 text-center text-sm text-fg-muted">
          No links generated.
        </p>
      )}

      {!loading && !ran && (
        <p className="rounded-xl border border-dashed border-line bg-surface/30 px-4 py-10 text-center text-sm text-fg-muted">
          {emptyPrompt}
        </p>
      )}
    </div>
  );
}

export function TextCloneView() {
  return (
    <LinkToolBase
      multiline
      placeholder="We never ask for your password or PIN…"
      button="Build dorks"
      hint="Generates search-engine dork links that hunt for pages copying this exact legitimate text (⌘/Ctrl+Enter to run)."
      loadingLabel="Generating clone-detection dork links…"
      emptyPrompt="Paste a distinctive block of legitimate site text to hunt for copycat pages."
      runner={(v) => textClone(v)}
    />
  );
}

export function PhishingDorksView() {
  return (
    <LinkToolBase
      multiline={false}
      placeholder="acme login, acme verify account"
      button="Build dorks"
      hint="Comma-separated keywords → phishing-detection dork links across Google, Bing, DuckDuckGo and Yahoo."
      loadingLabel="Generating phishing dork links…"
      emptyPrompt="Enter one or more keywords to generate phishing-detection dork links."
      runner={(v) =>
        phishingDorks(
          v
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
        )
      }
    />
  );
}
