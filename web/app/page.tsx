"use client";

import { useCallback, useEffect, useState } from "react";
import Header from "@/components/Header";
import Sidebar, { type TabKey } from "@/components/Sidebar";
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

const NAV_ITEMS = [
  { key: "search" as const, label: "Search", icon: <SearchIcon className="h-5 w-5" /> },
  { key: "domain" as const, label: "Domain Tools", icon: <BoltIcon className="h-5 w-5" /> },
  { key: "custom" as const, label: "Custom Platforms", icon: <LayersIcon className="h-5 w-5" /> },
  { key: "settings" as const, label: "Settings", icon: <SlidersIcon className="h-5 w-5" /> },
];

const SECTIONS: Record<TabKey, { title: string; desc: string }> = {
  search: {
    title: "Search",
    desc: "Generate OSINT search links across categorized platforms.",
  },
  domain: {
    title: "Domain Tools",
    desc: "Enrichment, lookalikes, clones, brand-abuse and combined scans.",
  },
  custom: {
    title: "Custom Platforms",
    desc: "Add and manage your own search platforms.",
  },
  settings: {
    title: "Settings",
    desc: "Network and request configuration for the API.",
  },
};

function ResultsSkeleton() {
  return (
    <div className="animate-fade-in flex flex-col gap-3">
      <div className="shimmer h-6 w-64 rounded-md" />
      <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
        {Array.from({ length: 7 }).map((_, i) => (
          <div
            key={i}
            className="flex items-center gap-3 border-b border-line-soft px-4 py-2.5 last:border-b-0"
          >
            <div className="shimmer h-4 w-32 rounded" />
            <div className="shimmer h-3 flex-1 rounded" />
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

  const section = SECTIONS[tab];

  return (
    <div className="flex h-screen flex-col">
      <Header />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar items={NAV_ITEMS} active={tab} onChange={setTab} />

        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-6 py-7">
            <div className="border-b border-line-soft pb-4">
              <h1 className="text-xl font-semibold text-fg">{section.title}</h1>
              <p className="mt-1 text-sm text-fg-muted">{section.desc}</p>
            </div>

            {tab === "search" && (
              <div className="flex flex-col gap-6">
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
                    <span className="font-mono text-fg">{displayTarget}</span>.
                    Try a different platform selection.
                  </div>
                ) : (
                  !error && <EmptyState />
                )}
              </div>
            )}

            {tab === "domain" && <DomainTools />}

            {tab === "custom" && <CustomPlatforms onChange={loadPlatforms} />}

            {tab === "settings" && <SettingsPanel />}
          </div>
        </main>
      </div>
    </div>
  );
}
