"use client";

import { useCallback, useEffect, useState } from "react";
import Header from "@/components/Header";
import Tabs, { type TabKey } from "@/components/Tabs";
import SearchPanel from "@/components/SearchPanel";
import ResultsPanel from "@/components/ResultsPanel";
import EmptyState from "@/components/EmptyState";
import SettingsPanel from "@/components/SettingsPanel";
import CustomPlatforms from "@/components/CustomPlatforms";
import DomainTools from "@/components/DomainTools";
import {
  AlertIcon,
  BoltIcon,
  LayersIcon,
  SearchIcon,
  SlidersIcon,
} from "@/components/icons";
import { fetchPlatforms, runSearch } from "@/lib/api";
import type {
  PlatformsResponse,
  SearchOptions,
  SearchResult,
} from "@/lib/types";

function ResultsSkeleton() {
  return (
    <div className="animate-fade-in flex flex-col gap-3">
      <div className="h-6 w-64 animate-pulse rounded bg-line-soft" />
      <div className="overflow-hidden rounded-xl border border-line bg-surface/60">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="flex items-center gap-3 border-b border-line-soft px-3 py-2.5 last:border-b-0"
          >
            <div className="h-4 w-32 animate-pulse rounded bg-line-soft" />
            <div className="h-3 flex-1 animate-pulse rounded bg-line-soft/70" />
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [tab, setTab] = useState<TabKey>("search");
  const [platformsData, setPlatformsData] = useState<PlatformsResponse | null>(
    null,
  );
  const [displayTarget, setDisplayTarget] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasSearched, setHasSearched] = useState(false);
  const [resultsKey, setResultsKey] = useState(0);

  const loadPlatforms = useCallback(() => {
    fetchPlatforms()
      .then(setPlatformsData)
      .catch(() =>
        setError(
          "Couldn't reach the Osiris API on localhost:8000. Is the backend running?",
        ),
      );
  }, []);

  useEffect(() => {
    loadPlatforms();
  }, [loadPlatforms]);

  async function handleSubmit(
    targets: string[],
    platforms: string[],
    options: SearchOptions,
  ) {
    setLoading(true);
    setError(null);
    setHasSearched(true);
    try {
      const response = await runSearch(targets, platforms, options);
      setDisplayTarget(response.targets.join(", "));
      setResults(response.results);
      setResultsKey((k) => k + 1);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Search failed. Confirm the Osiris API is running on localhost:8000.",
      );
      setResults([]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Header />
      <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-6 px-5 py-8">
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { key: "search", label: "Search", icon: <SearchIcon className="h-4 w-4" /> },
            { key: "domain", label: "Domain Tools", icon: <BoltIcon className="h-4 w-4" /> },
            { key: "custom", label: "Custom Platforms", icon: <LayersIcon className="h-4 w-4" /> },
            { key: "settings", label: "Settings", icon: <SlidersIcon className="h-4 w-4" /> },
          ]}
        />

        {tab === "search" && (
          <>
            <SearchPanel
              data={platformsData}
              loading={loading}
              onSubmit={handleSubmit}
            />

            {error && (
              <div
                role="alert"
                className="animate-fade-in flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger"
              >
                <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {loading ? (
              <ResultsSkeleton />
            ) : results.length > 0 ? (
              <ResultsPanel
                key={resultsKey}
                results={results}
                target={displayTarget}
              />
            ) : hasSearched && !error ? (
              <div className="rounded-xl border border-line bg-surface/40 px-4 py-12 text-center text-sm text-fg-muted">
                No links generated for{" "}
                <span className="font-mono text-fg">{displayTarget}</span>. Try a
                different platform selection.
              </div>
            ) : (
              !error && <EmptyState />
            )}
          </>
        )}

        {tab === "domain" && <DomainTools />}

        {tab === "custom" && <CustomPlatforms onChange={loadPlatforms} />}

        {tab === "settings" && <SettingsPanel />}
      </main>

      <footer className="mx-auto w-full max-w-5xl px-5 py-6">
        <p className="border-t border-line-soft pt-4 text-center text-xs text-fg-faint">
          Osiris generates OSINT search links · results open in your browser ·
          nothing is crawled server-side
        </p>
      </footer>
    </>
  );
}
