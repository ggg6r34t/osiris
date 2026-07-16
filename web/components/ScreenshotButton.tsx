"use client";

import { useEffect, useState } from "react";
import { screenshot } from "@/lib/api";
import { CameraIcon, CloseIcon } from "./icons";

/** Camera button that captures a headless screenshot of `url` in a modal. */
export default function ScreenshotButton({
  url,
  className = "",
}: {
  url: string;
  className?: string;
}) {
  const [open, setOpen] = useState(false);
  const [image, setImage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function openModal() {
    setOpen(true);
    if (image || loading) return; // capture once, then reuse
    setLoading(true);
    setError(null);
    screenshot(url)
      .then(setImage)
      .catch((e) => setError(e instanceof Error ? e.message : "Screenshot failed."))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={openModal}
        title="Screenshot"
        aria-label="Screenshot"
        className={`text-fg-faint transition-colors hover:text-accent ${className}`}
      >
        <CameraIcon className="h-4 w-4" />
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6 backdrop-blur-sm"
          onMouseDown={() => setOpen(false)}
        >
          <div
            className="animate-fade-in flex w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-line bg-surface-2 shadow-elevated"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
              <span className="truncate font-mono text-xs text-fg-muted" title={url}>
                {url}
              </span>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="text-fg-faint hover:text-fg"
                aria-label="Close"
              >
                <CloseIcon className="h-4 w-4" />
              </button>
            </div>
            <div className="flex min-h-[240px] items-center justify-center bg-canvas p-3">
              {loading && (
                <span className="flex items-center gap-2 text-sm text-fg-muted">
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-fg-faint/40 border-t-fg-muted" />
                  Capturing…
                </span>
              )}
              {!loading && error && (
                <p className="max-w-md text-center text-sm text-danger">{error}</p>
              )}
              {!loading && image && (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={image}
                  alt={`Screenshot of ${url}`}
                  className="max-h-[70vh] w-full rounded-lg border border-line object-contain"
                />
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
