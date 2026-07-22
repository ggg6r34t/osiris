"use client";

import { useRef, useState } from "react";
import { openLinks } from "@/lib/openLinks";
import { ExternalIcon } from "./icons";

const MIN = 50;
const MAX = 100;

/**
 * Opens a list of URLs in sequential, user-sized batches (50–100 per batch) so
 * the browser isn't overwhelmed by 200+ tabs at once. Each click opens the next
 * batch and advances; keep the same component mounted (or re-key it to reset).
 */
export default function BatchOpen({
  urls,
  randomize = false,
}: {
  urls: string[];
  randomize?: boolean;
}) {
  const [size, setSize] = useState(MIN);
  const [opened, setOpened] = useState(0);
  const [note, setNote] = useState<string | null>(null);
  // Order is fixed on first open (shuffled once if randomize). Built in the
  // event handler, not render, so Math.random stays out of the render path.
  const orderRef = useRef<string[] | null>(null);

  const clamp = Math.min(MAX, Math.max(MIN, Number(size) || MIN));
  const total = urls.length;
  const done = opened >= total;
  const start = opened + 1;
  const end = Math.min(opened + clamp, total);

  function openNext() {
    if (orderRef.current === null) {
      if (randomize) {
        const a = [...urls];
        for (let i = a.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [a[i], a[j]] = [a[j], a[i]];
        }
        orderRef.current = a;
      } else {
        orderRef.current = urls;
      }
    }
    const batch = orderRef.current.slice(opened, opened + clamp);
    if (!batch.length) return;
    const { opened: got, attempted } = openLinks(batch, { maxOpen: 0, randomize: false });
    setOpened((o) => Math.min(total, o + batch.length));
    setNote(
      got < attempted
        ? `Browser blocked ${attempted - got} of ${attempted} — allow pop-ups for this site, then continue.`
        : null,
    );
  }

  function reset() {
    setOpened(0);
    setNote(null);
    orderRef.current = null;
  }

  if (total === 0) return null;

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={openNext}
        disabled={done}
        className="inline-flex items-center gap-1.5 rounded-md bg-accent-gradient px-3 py-1.5 text-xs font-semibold text-white shadow-glow transition-colors hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
        title={done ? "All links opened" : `Open links ${start}–${end} of ${total} in new tabs`}
      >
        <ExternalIcon className="h-3.5 w-3.5" />
        {done
          ? `All ${total} opened`
          : total <= clamp
            ? `Open all ${total}`
            : opened === 0
              ? `Open batch (1–${end} of ${total})`
              : `Open next (${start}–${end} of ${total})`}
      </button>

      {total > clamp && (
        <label className="flex items-center gap-1.5 text-xs text-fg-muted" title="Links per batch (50–100)">
          batch
          <input
            type="number"
            min={MIN}
            max={MAX}
            value={size}
            onChange={(e) => setSize(Number(e.target.value))}
            className="w-16 rounded border border-line bg-surface px-2 py-1 text-fg outline-none focus:border-accent/60"
          />
        </label>
      )}

      {opened > 0 && !done && (
        <span className="font-mono text-[11px] text-fg-faint">{opened}/{total} opened</span>
      )}
      {opened > 0 && (
        <button type="button" onClick={reset} className="text-[11px] text-fg-faint hover:text-accent">
          reset
        </button>
      )}
      {note && <span className="font-mono text-[11px] text-amber-300">{note}</span>}
    </span>
  );
}
