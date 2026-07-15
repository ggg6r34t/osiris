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

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-line bg-surface/70 p-5 backdrop-blur"
    >
      <div className="mb-1.5 flex items-center justify-between">
        <label className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          {batch ? "Targets (one per line)" : "Target"}
        </label>
        <button
          type="button"
          onClick={() => setBatch((v) => !v)}
          className="text-xs text-fg-faint hover:text-accent"
        >
          {batch ? "Single target" : "Batch (multiple)"}
        </button>
      </div>

      <div className="flex flex-col gap-2.5 sm:flex-row">
        <div className="relative flex-1">
          {batch ? (
            <textarea
              value={batchText}
              onChange={(e) => setBatchText(e.target.value)}
              placeholder={"acme corp\nexample.com\n@handle"}
              rows={3}
              className="w-full resize-y rounded-lg border border-line bg-canvas px-3 py-2.5 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
            />
          ) : (
            <>
              <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-[18px] w-[18px] -translate-y-1/2 text-fg-faint" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="name, company, username, or domain…"
                autoFocus
                className="w-full rounded-lg border border-line bg-canvas py-2.5 pl-10 pr-3 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
              />
            </>
          )}
        </div>
        <button
          type="submit"
          disabled={submitDisabled}
          className="inline-flex h-[46px] items-center justify-center gap-2 self-start rounded-lg bg-accent px-5 text-sm font-semibold text-white transition-all hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? (
            <>
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/50 border-t-white" />
              Searching
            </>
          ) : (
            <>
              <SearchIcon className="h-4 w-4" />
              Search
            </>
          )}
        </button>
      </div>

      <div className="mt-4 border-t border-line-soft pt-4">
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
