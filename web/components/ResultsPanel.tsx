"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { checkUrls } from "@/lib/api";
import { openLinks } from "@/lib/openLinks";
import { safeHref } from "@/lib/url";
import type { CheckResult, SearchResult } from "@/lib/types";
import CopyButton from "./CopyButton";
import ExportMenu from "./ExportMenu";
import ScreenshotButton from "./ScreenshotButton";
import { isHttpUrl } from "@/lib/url";
import {
  BoltIcon,
  ChevronIcon,
  ExternalIcon,
  SearchIcon,
} from "./icons";

type ResultsPanelProps = {
  results: SearchResult[];
  target: string;
};

type CheckMap = Record<string, CheckResult>;

function IndeterminateCheckbox({
  checked,
  indeterminate,
  onChange,
  "aria-label": ariaLabel,
}: {
  checked: boolean;
  indeterminate: boolean;
  onChange: () => void;
  "aria-label"?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate && !checked;
  }, [indeterminate, checked]);
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      onChange={onChange}
      aria-label={ariaLabel}
      onClick={(e) => e.stopPropagation()}
      className="accent-[var(--color-accent)]"
    />
  );
}

function ScoreBadge({ label, score, reasons }: SearchResult) {
  if (label === undefined) return null;
  const color =
    label === "HIGH"
      ? "border-danger/40 bg-danger/10 text-danger"
      : label === "MEDIUM"
        ? "border-amber-400/40 bg-amber-400/10 text-amber-400"
        : label === "LOW"
          ? "border-accent/40 bg-accent/10 text-accent"
          : "border-line bg-surface text-fg-faint";
  return (
    <span
      title={(reasons ?? []).join(" · ")}
      className={`shrink-0 rounded border px-1.5 py-px font-mono text-[10px] ${color}`}
    >
      {label} {score}
    </span>
  );
}

function StatusDot({ status }: { status?: CheckResult }) {
  if (!status) return null;
  return (
    <span
      title={status.ok ? `Reachable (${status.status})` : "Unreachable"}
      className={`h-2 w-2 shrink-0 rounded-full ${
        status.ok
          ? "bg-live shadow-[0_0_8px_0_var(--color-live)]"
          : "bg-danger shadow-[0_0_8px_0_var(--color-danger)]"
      }`}
    />
  );
}

function ResultRow({
  result,
  selected,
  onToggle,
  status,
  showTarget,
}: {
  result: SearchResult;
  selected: boolean;
  onToggle: () => void;
  status?: CheckResult;
  showTarget: boolean;
}) {
  return (
    <div className="group flex items-center gap-3 px-4 py-2 transition-colors hover:bg-accent/[0.05]">
      <IndeterminateCheckbox
        checked={selected}
        indeterminate={false}
        onChange={onToggle}
        aria-label={`Select ${result.platform}`}
      />
      <StatusDot status={status} />
      <span
        className="flex w-36 shrink-0 items-center gap-1.5 truncate text-sm text-fg"
        title={result.platform}
      >
        {result.platform}
      </span>
      {showTarget && (
        <span className="w-24 shrink-0 truncate font-mono text-[11px] text-fg-faint" title={result.target}>
          {result.target}
        </span>
      )}
      <a
        href={safeHref(result.url)}
        target="_blank"
        rel="noopener noreferrer"
        title={result.url}
        className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted transition-colors hover:text-accent"
      >
        {result.url}
      </a>
      <ScoreBadge {...result} />
      <div className="flex shrink-0 items-center gap-2 opacity-60 transition-opacity group-hover:opacity-100">
        {isHttpUrl(result.url) && <ScreenshotButton url={result.url} />}
        <CopyButton value={result.url} title="Copy URL" />
        <a
          href={safeHref(result.url)}
          target="_blank"
          rel="noopener noreferrer"
          title="Open in new tab"
          className="text-fg-faint transition-colors hover:text-accent"
        >
          <ExternalIcon className="h-4 w-4" />
        </a>
      </div>
    </div>
  );
}

export default function ResultsPanel({ results, target }: ResultsPanelProps) {
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [checks, setChecks] = useState<CheckMap>({});
  const [checking, setChecking] = useState(false);
  const [reachableOnly, setReachableOnly] = useState(false);

  const [maxOpen, setMaxOpen] = useState("0");
  const [randomize, setRandomize] = useState(false);
  const [openNote, setOpenNote] = useState<string | null>(null);

  // Transient state (selection/checks/filter) resets automatically: page.tsx
  // remounts this panel via a per-search `key` when a new result set arrives.
  const scoreActive = results.some((r) => r.score !== undefined);
  const showTarget = new Set(results.map((r) => r.target)).size > 1;

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return results.filter((r) => {
      if (reachableOnly && !checks[r.url]?.ok) return false;
      if (!q) return true;
      return (
        r.platform.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        r.url.toLowerCase().includes(q) ||
        (r.target ?? "").toLowerCase().includes(q)
      );
    });
  }, [results, filter, reachableOnly, checks]);

  const groups = useMemo(() => {
    const m = new Map<string, SearchResult[]>();
    for (const r of filtered) {
      const list = m.get(r.category);
      if (list) list.push(r);
      else m.set(r.category, [r]);
    }
    return m;
  }, [filtered]);

  const filterActive = filter.trim().length > 0 || reachableOnly;

  function toggleUrl(url: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      return next;
    });
  }

  function setGroupSelected(urls: string[], on: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const u of urls) {
        if (on) next.add(u);
        else next.delete(u);
      }
      return next;
    });
  }

  const allVisibleUrls = filtered.map((r) => r.url);
  const allSelected =
    allVisibleUrls.length > 0 && allVisibleUrls.every((u) => selected.has(u));
  const someSelected = allVisibleUrls.some((u) => selected.has(u));

  async function runCheck() {
    setChecking(true);
    try {
      const res = await checkUrls(allVisibleUrls);
      setChecks((prev) => {
        const next = { ...prev };
        for (const r of res) next[r.url] = r;
        return next;
      });
    } catch {
      /* surfaced by disabled state; keep UI responsive */
    } finally {
      setChecking(false);
    }
  }

  function openSelected() {
    const urls = filtered.filter((r) => selected.has(r.url)).map((r) => r.url);
    const { opened, attempted } = openLinks(urls, {
      maxOpen: Math.max(0, parseInt(maxOpen || "0", 10) || 0),
      randomize,
    });
    setOpenNote(
      opened < attempted
        ? `Opened ${opened} of ${attempted}. Your browser blocked the rest — allow pop-ups for this site, then try again.`
        : null,
    );
  }

  const selectedUrls = filtered
    .filter((r) => selected.has(r.url))
    .map((r) => r.url);

  return (
    <section className="animate-fade-in flex flex-col gap-3">
      {/* Summary + primary controls */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-baseline gap-2 text-sm">
          <span className="font-mono text-lg font-semibold text-fg">
            {filtered.length}
          </span>
          <span className="text-fg-muted">
            {filtered.length === 1 ? "link" : "links"}
            {filterActive && (
              <span className="text-fg-faint"> of {results.length}</span>
            )}{" "}
            · {groups.size} {groups.size === 1 ? "category" : "categories"}
          </span>
          <span className="text-fg-faint">·</span>
          <span className="truncate font-mono text-sm text-fg-muted" title={target}>
            {target}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter results…"
              className="w-40 rounded-md border border-line bg-surface py-1.5 pl-8 pr-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/60"
            />
          </div>
          <button
            type="button"
            onClick={runCheck}
            disabled={checking || filtered.length === 0}
            className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:text-fg disabled:opacity-40"
          >
            {checking ? (
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-fg-faint/40 border-t-fg-muted" />
            ) : (
              <BoltIcon className="h-4 w-4" />
            )}
            Check
          </button>
          {Object.keys(checks).length > 0 && (
            <button
              type="button"
              onClick={() => setReachableOnly((v) => !v)}
              className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
                reachableOnly
                  ? "border-live/40 bg-live/10 text-live"
                  : "border-line bg-surface text-fg-muted hover:text-fg"
              }`}
            >
              Reachable only
            </button>
          )}
          <CopyButton
            value={filtered.map((r) => r.url).join("\n")}
            label="Copy all"
            withText
            className="rounded-md border border-line bg-surface px-3 py-1.5"
          />
          <ExportMenu
            results={filtered}
            target={target}
            disabled={filtered.length === 0}
          />
        </div>
      </div>

      {/* Selection toolbar */}
      {someSelected && (
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2 text-sm">
          <span className="font-medium text-accent">
            {selectedUrls.length} selected
          </span>
          <button
            type="button"
            onClick={openSelected}
            className="inline-flex items-center gap-1.5 rounded-md bg-accent-gradient shadow-glow px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-accent-strong"
          >
            <ExternalIcon className="h-3.5 w-3.5" />
            Open selected
          </button>
          <label className="flex items-center gap-1.5 text-xs text-fg-muted">
            max
            <input
              type="number"
              min={0}
              value={maxOpen}
              onChange={(e) => setMaxOpen(e.target.value)}
              className="w-16 rounded border border-line bg-surface px-2 py-1 text-fg outline-none focus:border-accent/60"
            />
          </label>
          <label className="flex items-center gap-1.5 text-xs text-fg-muted">
            <input
              type="checkbox"
              checked={randomize}
              onChange={(e) => setRandomize(e.target.checked)}
              className="accent-[var(--color-accent)]"
            />
            randomize
          </label>
          <CopyButton
            value={selectedUrls.join("\n")}
            label="Copy selected"
            withText
            className="text-fg-muted"
          />
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            className="ml-auto text-xs text-fg-faint hover:text-danger"
          >
            Clear
          </button>
        </div>
      )}

      {openNote && (
        <p className="animate-fade-in rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-xs text-amber-400">
          {openNote}
        </p>
      )}

      {/* Results */}
      <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
        {filtered.length === 0 ? (
          <div className="px-4 py-12 text-center text-sm text-fg-muted">
            No results match the current filter.
          </div>
        ) : (
          <>
            {/* Select-all header */}
            <label className="flex items-center gap-2.5 border-b border-line-soft bg-canvas/40 px-3 py-2 text-xs text-fg-muted">
              <IndeterminateCheckbox
                checked={allSelected}
                indeterminate={someSelected}
                onChange={() => setGroupSelected(allVisibleUrls, !allSelected)}
                aria-label="Select all"
              />
              Select all {filtered.length}
              {scoreActive && (
                <span className="ml-auto font-mono text-[10px] text-fg-faint">
                  scored
                </span>
              )}
            </label>

            {[...groups.entries()].map(([category, rows]) => {
              const catUrls = rows.map((r) => r.url);
              const catAll = catUrls.every((u) => selected.has(u));
              const catSome = catUrls.some((u) => selected.has(u));
              const isCollapsed = !filterActive && collapsed.has(category);
              return (
                <div key={category}>
                  <div className="flex items-center gap-2.5 bg-white/[0.015] px-4 py-2.5 transition-colors hover:bg-white/[0.03]">
                    <IndeterminateCheckbox
                      checked={catAll}
                      indeterminate={catSome}
                      onChange={() => setGroupSelected(catUrls, !catAll)}
                      aria-label={`Select ${category}`}
                    />
                    <button
                      type="button"
                      onClick={() =>
                        setCollapsed((prev) => {
                          const next = new Set(prev);
                          if (next.has(category)) next.delete(category);
                          else next.add(category);
                          return next;
                        })
                      }
                      className="flex flex-1 items-center gap-2.5 text-left"
                    >
                      <ChevronIcon
                        className={`h-4 w-4 shrink-0 text-fg-faint transition-transform duration-200 ${
                          isCollapsed ? "-rotate-90" : ""
                        }`}
                      />
                      <span className="font-mono text-xs font-medium uppercase tracking-wider text-accent">
                        {category}
                      </span>
                      <span className="h-px flex-1 bg-line-soft" />
                      <span className="rounded-full border border-line bg-canvas px-2 py-0.5 font-mono text-[10px] tabular-nums text-fg-muted">
                        {rows.length}
                      </span>
                    </button>
                  </div>
                  {!isCollapsed && (
                    <div className="divide-y divide-line-soft/60 border-b border-line-soft">
                      {rows.map((r, i) => (
                        <ResultRow
                          key={`${r.url}-${i}`}
                          result={r}
                          selected={selected.has(r.url)}
                          onToggle={() => toggleUrl(r.url)}
                          status={checks[r.url]}
                          showTarget={showTarget}
                        />
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </>
        )}
      </div>
    </section>
  );
}
