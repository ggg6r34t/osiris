"use client";

import { useMemo, useState } from "react";
import type { PlatformsResponse } from "@/lib/types";
import { ChevronIcon, CloseIcon, SearchIcon } from "./icons";

export type PickerMode = "all" | "select";

type PlatformPickerProps = {
  data: PlatformsResponse | null;
  mode: PickerMode;
  onModeChange: (mode: PickerMode) => void;
  selectedCategories: Set<string>;
  selectedPlatforms: Set<string>;
  onToggleCategory: (category: string) => void;
  onTogglePlatform: (platform: string) => void;
  onClear: () => void;
};

export default function PlatformPicker({
  data,
  mode,
  onModeChange,
  selectedCategories,
  selectedPlatforms,
  onToggleCategory,
  onTogglePlatform,
  onClear,
}: PlatformPickerProps) {
  const [expanded, setExpanded] = useState(false);
  const [filter, setFilter] = useState("");

  const totalLinks = useMemo(() => {
    if (!data) return 0;
    return Object.values(data.platforms).reduce((n, list) => n + list.length, 0);
  }, [data]);

  const filteredPlatforms = useMemo(() => {
    if (!data) return [] as { name: string; category: string }[];
    const q = filter.trim().toLowerCase();
    const flat: { name: string; category: string }[] = [];
    for (const category of data.categories) {
      for (const name of data.platforms[category] ?? []) {
        if (!q || name.toLowerCase().includes(q)) flat.push({ name, category });
      }
    }
    return flat.slice(0, 60);
  }, [data, filter]);

  const selectionCount = selectedCategories.size + selectedPlatforms.size;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          Platforms
        </span>
        <div className="flex rounded-md border border-line bg-canvas p-0.5 text-xs">
          {(["all", "select"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => onModeChange(m)}
              className={`rounded px-2.5 py-1 font-medium transition-colors ${
                mode === m
                  ? "bg-accent/15 text-accent"
                  : "text-fg-muted hover:text-fg"
              }`}
            >
              {m === "all" ? "All" : "Select"}
            </button>
          ))}
        </div>
      </div>

      {mode === "all" ? (
        <p className="rounded-md border border-line-soft bg-canvas px-3 py-2.5 text-sm text-fg-muted">
          Searching{" "}
          <span className="font-mono text-fg">{totalLinks || "…"}</span> links
          across{" "}
          <span className="font-mono text-fg">
            {data?.categories.length ?? "…"}
          </span>{" "}
          categories.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          {/* Category chips */}
          <div className="flex flex-wrap gap-1.5">
            {data?.categories.map((category) => {
              const active = selectedCategories.has(category);
              const count = data.platforms[category]?.length ?? 0;
              return (
                <button
                  key={category}
                  type="button"
                  onClick={() => onToggleCategory(category)}
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-xs transition-colors ${
                    active
                      ? "border-accent/40 bg-accent/10 text-accent"
                      : "border-line bg-surface text-fg-muted hover:border-line hover:text-fg"
                  }`}
                >
                  {category}
                  <span
                    className={active ? "text-accent/70" : "text-fg-faint"}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Selected individual platforms */}
          {selectedPlatforms.size > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {[...selectedPlatforms].map((name) => (
                <span
                  key={name}
                  className="inline-flex items-center gap-1 rounded-md border border-accent/30 bg-accent/10 px-2 py-0.5 text-xs text-accent"
                >
                  {name}
                  <button
                    type="button"
                    onClick={() => onTogglePlatform(name)}
                    aria-label={`Remove ${name}`}
                    className="text-accent/60 hover:text-accent"
                  >
                    <CloseIcon className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          )}

          {/* Specific-platform search */}
          <div className="rounded-md border border-line-soft bg-canvas">
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="flex w-full items-center justify-between px-3 py-2 text-xs text-fg-muted hover:text-fg"
            >
              <span>Add specific platforms</span>
              <ChevronIcon
                className={`h-4 w-4 transition-transform ${
                  expanded ? "rotate-180" : ""
                }`}
              />
            </button>

            {expanded && (
              <div className="border-t border-line-soft p-2">
                <div className="relative mb-2">
                  <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-faint" />
                  <input
                    type="text"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Filter platforms…"
                    className="w-full rounded border border-line bg-surface py-1.5 pl-8 pr-2 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60"
                  />
                </div>
                <div className="flex max-h-48 flex-wrap gap-1.5 overflow-y-auto">
                  {filteredPlatforms.map(({ name, category }) => {
                    const active = selectedPlatforms.has(name);
                    const covered = selectedCategories.has(category);
                    return (
                      <button
                        key={`${category}:${name}`}
                        type="button"
                        onClick={() => onTogglePlatform(name)}
                        title={covered ? `Covered by ${category}` : category}
                        className={`rounded border px-2 py-0.5 text-xs transition-colors ${
                          active
                            ? "border-accent/40 bg-accent/10 text-accent"
                            : covered
                              ? "border-line-soft bg-surface text-fg-faint"
                              : "border-line bg-surface text-fg-muted hover:text-fg"
                        }`}
                      >
                        {name}
                      </button>
                    );
                  })}
                  {filteredPlatforms.length === 0 && (
                    <span className="px-1 py-2 text-xs text-fg-faint">
                      No platforms match “{filter}”.
                    </span>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Selection summary */}
          <div className="flex items-center justify-between text-xs text-fg-muted">
            <span>
              {selectionCount === 0 ? (
                <span className="text-fg-faint">
                  Select at least one category or platform.
                </span>
              ) : (
                <>
                  <span className="font-mono text-fg">
                    {selectedCategories.size}
                  </span>{" "}
                  categories ·{" "}
                  <span className="font-mono text-fg">
                    {selectedPlatforms.size}
                  </span>{" "}
                  platforms
                </>
              )}
            </span>
            {selectionCount > 0 && (
              <button
                type="button"
                onClick={onClear}
                className="text-fg-faint hover:text-danger"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
