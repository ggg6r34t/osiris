"use client";

import { useEffect, useRef, useState } from "react";
import { addCaseItem, createCase, getCases } from "@/lib/api";
import type { CaseSummary } from "@/lib/types";
import { CheckIcon, PlusIcon } from "./icons";

/** Add a finding (kind + data) to an existing or new case. */
export default function AddToCase({
  kind,
  data,
}: {
  kind: string;
  data: Record<string, unknown>;
}) {
  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [newName, setNewName] = useState("");
  const [added, setAdded] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) getCases().then(setCases).catch(() => setCases([]));
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  async function addTo(caseId: number) {
    await addCaseItem(caseId, { kind, data });
    setOpen(false);
    setAdded(true);
    setTimeout(() => setAdded(false), 1600);
  }
  async function addNew() {
    const n = newName.trim();
    if (!n) return;
    const c = await createCase(n);
    setNewName("");
    await addTo(c.id);
  }

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
          added
            ? "border-live/40 bg-live/10 text-live"
            : "border-line bg-surface text-fg-muted hover:text-fg"
        }`}
      >
        {added ? <CheckIcon className="h-4 w-4" /> : <PlusIcon className="h-4 w-4" />}
        {added ? "Added" : "Add to case"}
      </button>

      {open && (
        <div className="absolute right-0 z-30 mt-1.5 w-60 overflow-hidden rounded-lg border border-line bg-surface-2 shadow-elevated">
          <div className="max-h-52 overflow-y-auto">
            {cases.length === 0 ? (
              <p className="px-3 py-3 text-xs text-fg-faint">No cases yet.</p>
            ) : (
              cases.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  onClick={() => addTo(c.id)}
                  className="flex w-full items-center justify-between px-3 py-2 text-left text-sm text-fg-muted transition-colors hover:bg-accent/10 hover:text-accent"
                >
                  <span className="truncate">{c.name}</span>
                  <span className="ml-2 font-mono text-[10px] text-fg-faint">
                    {c.item_count}
                  </span>
                </button>
              ))
            )}
          </div>
          <div className="flex gap-1.5 border-t border-line-soft p-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addNew()}
              placeholder="New case…"
              className="flex-1 rounded border border-line bg-canvas px-2 py-1 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60"
            />
            <button
              type="button"
              onClick={addNew}
              className="rounded bg-accent-gradient px-2 py-1 text-xs font-semibold text-white"
            >
              Add
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
