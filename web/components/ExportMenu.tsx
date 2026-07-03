"use client";

import { useEffect, useRef, useState } from "react";
import { toCsv, toJson, toTxt, triggerDownload } from "@/lib/export";
import type { SearchResult } from "@/lib/types";
import { ChevronIcon, DownloadIcon } from "./icons";

type ExportMenuProps = {
  results: SearchResult[];
  target: string;
  disabled?: boolean;
};

const FORMATS = [
  { key: "csv", label: "CSV", mime: "text/csv", build: toCsv },
  { key: "json", label: "JSON", mime: "application/json", build: toJson },
  { key: "txt", label: "TXT", mime: "text/plain", build: toTxt },
] as const;

export default function ExportMenu({
  results,
  target,
  disabled = false,
}: ExportMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const baseName = `osiris-${target.trim().replace(/\s+/g, "_") || "results"}`;

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 rounded-md border border-line bg-surface px-3 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:text-fg disabled:cursor-not-allowed disabled:opacity-40"
      >
        <DownloadIcon className="h-4 w-4" />
        Export
        <ChevronIcon
          className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div className="absolute right-0 z-30 mt-1.5 w-40 overflow-hidden rounded-md border border-line bg-surface-2 shadow-xl shadow-black/40">
          <div className="border-b border-line-soft px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fg-faint">
            {results.length} rows
          </div>
          {FORMATS.map((fmt) => (
            <button
              key={fmt.key}
              type="button"
              onClick={() => {
                triggerDownload(
                  `${baseName}.${fmt.key}`,
                  fmt.build(results),
                  fmt.mime,
                );
                setOpen(false);
              }}
              className="flex w-full items-center justify-between px-3 py-2 text-sm text-fg-muted transition-colors hover:bg-accent/10 hover:text-accent"
            >
              {fmt.label}
              <span className="font-mono text-[10px] text-fg-faint">
                .{fmt.key}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
