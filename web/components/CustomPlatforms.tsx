"use client";

import { useEffect, useState, type FormEvent } from "react";
import {
  addCustomPlatform,
  getCustomPlatforms,
  removeCustomPlatform,
} from "@/lib/api";
import type { CustomPlatformMap } from "@/lib/types";
import { PlusIcon, TrashIcon } from "./icons";

type CustomPlatformsProps = {
  onChange: () => void; // notify parent to refetch the platform picker
};

export default function CustomPlatforms({ onChange }: CustomPlatformsProps) {
  const [platforms, setPlatforms] = useState<CustomPlatformMap>({});
  const [category, setCategory] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getCustomPlatforms()
      .then(setPlatforms)
      .catch(() => setError("Couldn't load custom platforms."));
  }, []);

  const existingCategories = Object.keys(platforms);

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const lower = url.trim().toLowerCase();
    if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
      setError("URL must start with http:// or https://.");
      return;
    }
    if (!url.includes("{query}")) {
      setError("URL must include the {query} placeholder.");
      return;
    }
    setBusy(true);
    try {
      const next = await addCustomPlatform(category.trim(), name.trim(), url.trim());
      setPlatforms(next);
      setName("");
      setUrl("");
      onChange();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add platform.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRemove(cat: string, platform: string) {
    setBusy(true);
    setError(null);
    try {
      const next = await removeCustomPlatform(cat, platform);
      setPlatforms(next);
      onChange();
    } catch {
      setError("Failed to remove platform.");
    } finally {
      setBusy(false);
    }
  }

  const field =
    "rounded-md border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none placeholder:text-fg-faint focus:border-accent/60";
  const entries = Object.entries(platforms);

  return (
    <div className="animate-fade-in flex flex-col gap-5">
      {/* Add form */}
      <form
        onSubmit={handleAdd}
        className="max-w-2xl rounded-xl border border-line bg-surface/70 p-5"
      >
        <h2 className="text-base font-medium text-fg">Add custom platform</h2>
        <p className="mt-1 text-sm text-fg-muted">
          The URL template must contain{" "}
          <code className="rounded bg-canvas px-1 font-mono text-accent">
            {"{query}"}
          </code>{" "}
          where the target is substituted.
        </p>

        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Category
            <input
              className={field}
              list="custom-categories"
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="web"
              required
            />
            <datalist id="custom-categories">
              {existingCategories.map((c) => (
                <option key={c} value={c} />
              ))}
            </datalist>
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Name
            <input
              className={field}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My Engine"
              required
            />
          </label>
        </div>
        <label className="mt-3 flex flex-col gap-1 text-xs text-fg-muted">
          URL template
          <input
            className={`${field} font-mono`}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/search?q={query}"
            required
          />
        </label>

        {error && <p className="mt-3 text-sm text-danger">{error}</p>}

        <button
          type="submit"
          disabled={busy}
          className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-strong disabled:opacity-40"
        >
          <PlusIcon className="h-4 w-4" />
          Add platform
        </button>
      </form>

      {/* Existing */}
      <div className="max-w-2xl rounded-xl border border-line bg-surface/60">
        <div className="border-b border-line-soft px-4 py-2.5 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          User-added platforms
        </div>
        {entries.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-fg-muted">
            No custom platforms yet.
          </p>
        ) : (
          entries.map(([cat, items]) => (
            <div key={cat}>
              <div className="flex items-center gap-2.5 px-4 py-2">
                <span className="font-mono text-xs uppercase tracking-wider text-accent">
                  {cat}
                </span>
                <span className="h-px flex-1 bg-line-soft" />
              </div>
              <div className="divide-y divide-line-soft/60 border-b border-line-soft">
                {Object.entries(items).map(([platform, tpl]) => (
                  <div
                    key={platform}
                    className="group flex items-center gap-3 px-4 py-2"
                  >
                    <span className="w-32 shrink-0 truncate text-sm text-fg">
                      {platform}
                    </span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted" title={tpl}>
                      {tpl}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleRemove(cat, platform)}
                      disabled={busy}
                      title="Remove"
                      className="text-fg-faint transition-colors hover:text-danger disabled:opacity-40"
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
