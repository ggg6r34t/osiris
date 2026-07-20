"use client";

import { useState, type FormEvent, type ReactNode } from "react";
import type { PlatformsResponse, SearchOptions } from "@/lib/types";
import PlatformPicker, { type PickerMode } from "./PlatformPicker";
import { ChevronIcon, SearchIcon } from "./icons";

type SearchPanelProps = {
  data: PlatformsResponse | null;
  loading: boolean;
  onSubmit: (
    targets: string[],
    platforms: string[],
    options: SearchOptions,
  ) => void;
};

function CheckRow({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <label
      className={`flex items-center gap-2 text-sm ${
        disabled ? "text-fg-faint" : "text-fg-muted"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-[var(--color-accent)]"
      />
      {children}
    </label>
  );
}

function splitList(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// Investigation-type presets → category selection (empty = all platforms).
const PRESETS: { label: string; categories: string[] }[] = [
  { label: "All", categories: [] },
  { label: "Trademark", categories: ["marketplace", "mobile_apps", "social_networks", "web"] },
  { label: "People", categories: ["social_networks", "osint_engines"] },
  { label: "Scams", categories: ["marketplace", "social_networks", "phishing_detection"] },
  { label: "Phishing", categories: ["phishing_detection", "cyber_intel", "osint_engines"] },
  { label: "Web", categories: ["web", "osint_engines"] },
];

export default function SearchPanel({
  data,
  loading,
  onSubmit,
}: SearchPanelProps) {
  const [target, setTarget] = useState("");
  const [batch, setBatch] = useState(false);
  const [batchText, setBatchText] = useState("");

  const [mode, setMode] = useState<PickerMode>("all");
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(
    new Set(),
  );
  const [selectedPlatforms, setSelectedPlatforms] = useState<Set<string>>(
    new Set(),
  );

  const [optionsOpen, setOptionsOpen] = useState(false);
  const [fuzzy, setFuzzy] = useState(false);
  const [dedupe, setDedupe] = useState(false);
  const [score, setScore] = useState(false);
  const [sortScore, setSortScore] = useState(false);
  const [log, setLog] = useState(false);
  const [maxLinks, setMaxLinks] = useState("0");
  const [tag, setTag] = useState("");
  const [excludePlatforms, setExcludePlatforms] = useState("");
  const [excludeCategories, setExcludeCategories] = useState("");

  function toggle(set: Set<string>, value: string): Set<string> {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    return next;
  }

  function applyPreset(categories: string[]) {
    if (categories.length === 0) {
      setMode("all");
      setSelectedCategories(new Set());
      setSelectedPlatforms(new Set());
      return;
    }
    setMode("select");
    setSelectedPlatforms(new Set());
    setSelectedCategories(new Set(categories.filter((c) => data?.categories.includes(c))));
  }

  function currentTargets(): string[] {
    return batch
      ? splitList(batchText)
      : target.trim()
        ? [target.trim()]
        : [];
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const targets = currentTargets();
    if (targets.length === 0) return;

    const platforms =
      mode === "all" ? ["all"] : [...selectedCategories, ...selectedPlatforms];
    if (mode === "select" && platforms.length === 0) return;

    onSubmit(targets, platforms, {
      fuzzy,
      dedupe,
      score,
      sortScore: score && sortScore,
      maxLinks: Math.max(0, parseInt(maxLinks || "0", 10) || 0),
      excludePlatforms: splitList(excludePlatforms),
      excludeCategories: splitList(excludeCategories),
      tag: tag.trim(),
      log,
    });
  }

  const selectionEmpty =
    mode === "select" &&
    selectedCategories.size === 0 &&
    selectedPlatforms.size === 0;
  const submitDisabled =
    loading || currentTargets().length === 0 || selectionEmpty;

  const activeOptions = [
    fuzzy && "fuzzy",
    dedupe && "dedupe",
    score && "score",
    score && sortScore && "sort",
    log && "log",
    parseInt(maxLinks || "0", 10) > 0 && `max ${maxLinks}`,
    tag.trim() && "tag",
    splitList(excludePlatforms).length && "exclude",
  ].filter(Boolean) as string[];

  const submitInner = loading ? (
    <>
      <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/50 border-t-white" />
      Searching
    </>
  ) : (
    <>
      <SearchIcon className="h-4 w-4" />
      Search
    </>
  );

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-2xl border border-line bg-surface/70 p-6 shadow-card backdrop-blur"
    >
      {/* Hero */}
      <div className="flex flex-col items-center px-2 pb-1 pt-2 text-center">
        <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-accent-gradient shadow-glow ring-4 ring-accent/10">
          <SearchIcon className="h-7 w-7 text-white" />
        </div>
        <h2 className="text-2xl font-semibold tracking-tight text-fg">
          Search across platforms
        </h2>
        <p className="mt-2 max-w-xl text-sm text-fg-muted">
          Generate OSINT search links for a name, company, username, or domain across
          categorized platforms — then open, check, score, and export the results.
        </p>

        <div className="mt-6 w-full max-w-2xl">
          {batch ? (
            <textarea
              value={batchText}
              onChange={(e) => setBatchText(e.target.value)}
              placeholder={"acme corp\nexample.com\n@handle"}
              rows={3}
              className="w-full resize-y rounded-xl border border-line bg-canvas px-3 py-2.5 text-left text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
            />
          ) : (
            <div className="flex items-center gap-2 rounded-xl border border-line bg-canvas py-1.5 pl-3 pr-1.5 text-left transition-colors focus-within:border-accent/70 focus-within:ring-2 focus-within:ring-accent/20">
              <SearchIcon className="pointer-events-none h-[18px] w-[18px] shrink-0 text-fg-faint" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="name, company, username, or domain…"
                autoFocus
                className="min-w-0 flex-1 bg-transparent py-1.5 text-[15px] text-fg outline-none placeholder:text-fg-faint"
              />
              <button
                type="submit"
                disabled={submitDisabled}
                className="inline-flex h-[40px] shrink-0 items-center justify-center gap-2 rounded-lg bg-accent-gradient px-4 text-sm font-semibold text-white shadow-glow transition-all hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
              >
                {submitInner}
              </button>
            </div>
          )}

          {batch && (
            <button
              type="submit"
              disabled={submitDisabled}
              className="mt-2.5 inline-flex h-[44px] w-full items-center justify-center gap-2 rounded-xl bg-accent-gradient px-5 text-sm font-semibold text-white shadow-glow transition-all hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
            >
              {submitInner}
            </button>
          )}
        </div>

        <button
          type="button"
          onClick={() => setBatch((v) => !v)}
          className="mt-3 text-xs text-fg-faint transition-colors hover:text-accent"
        >
          {batch ? "← Single target" : "Batch (multiple targets)"}
        </button>
      </div>

      <div className="mt-5 border-t border-line-soft pt-4">
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          <span className="mr-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
            Preset
          </span>
          {PRESETS.map((preset) => (
            <button
              key={preset.label}
              type="button"
              onClick={() => applyPreset(preset.categories)}
              title={preset.categories.join(", ") || "all categories"}
              className="rounded-md border border-line bg-surface px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent/40 hover:text-accent"
            >
              {preset.label}
            </button>
          ))}
        </div>
        <PlatformPicker
          data={data}
          mode={mode}
          onModeChange={setMode}
          selectedCategories={selectedCategories}
          selectedPlatforms={selectedPlatforms}
          onToggleCategory={(c) => setSelectedCategories((s) => toggle(s, c))}
          onTogglePlatform={(p) => setSelectedPlatforms((s) => toggle(s, p))}
          onClear={() => {
            setSelectedCategories(new Set());
            setSelectedPlatforms(new Set());
          }}
        />
      </div>

      {/* Options */}
      <div className="mt-4 rounded-lg border border-line-soft bg-canvas">
        <button
          type="button"
          onClick={() => setOptionsOpen((v) => !v)}
          className="flex w-full items-center justify-between px-3 py-2.5 text-sm text-fg-muted hover:text-fg"
        >
          <span className="flex items-center gap-2">
            Options
            {activeOptions.length > 0 && (
              <span className="flex flex-wrap gap-1">
                {activeOptions.map((o) => (
                  <span
                    key={o}
                    className="rounded border border-accent/30 bg-accent/10 px-1.5 py-px font-mono text-[10px] text-accent"
                  >
                    {o}
                  </span>
                ))}
              </span>
            )}
          </span>
          <ChevronIcon
            className={`h-4 w-4 transition-transform ${optionsOpen ? "rotate-180" : ""}`}
          />
        </button>

        {optionsOpen && (
          <div className="flex flex-col gap-4 border-t border-line-soft p-4">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <CheckRow checked={fuzzy} onChange={setFuzzy}>
                Fuzzy match
              </CheckRow>
              <CheckRow checked={dedupe} onChange={setDedupe}>
                Deduplicate URLs
              </CheckRow>
              <CheckRow checked={log} onChange={setLog}>
                Log to server
              </CheckRow>
              <CheckRow checked={score} onChange={setScore}>
                Threat scoring
              </CheckRow>
              <CheckRow
                checked={sortScore}
                onChange={setSortScore}
                disabled={!score}
              >
                Sort by score
              </CheckRow>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-xs text-fg-muted">
                Max links (0 = no limit)
                <input
                  type="number"
                  min={0}
                  value={maxLinks}
                  onChange={(e) => setMaxLinks(e.target.value)}
                  className="rounded border border-line bg-surface px-2.5 py-1.5 text-sm text-fg outline-none focus:border-accent/60"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-fg-muted">
                Tag (for exports / logs)
                <input
                  type="text"
                  value={tag}
                  onChange={(e) => setTag(e.target.value)}
                  placeholder="case-1234"
                  className="rounded border border-line bg-surface px-2.5 py-1.5 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-fg-muted">
                Exclude platforms (comma-separated)
                <input
                  type="text"
                  value={excludePlatforms}
                  onChange={(e) => setExcludePlatforms(e.target.value)}
                  placeholder="Twitter, TikTok"
                  className="rounded border border-line bg-surface px-2.5 py-1.5 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-fg-muted">
                Exclude categories (comma-separated)
                <input
                  type="text"
                  value={excludeCategories}
                  onChange={(e) => setExcludeCategories(e.target.value)}
                  placeholder="mobile_apps"
                  className="rounded border border-line bg-surface px-2.5 py-1.5 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60"
                />
              </label>
            </div>
          </div>
        )}
      </div>
    </form>
  );
}
