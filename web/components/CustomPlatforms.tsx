"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  addCustomPlatform,
  fetchPlatforms,
  getCustomPlatforms,
  importCustomPlatforms,
  removeCustomPlatform,
} from "@/lib/api";
import { triggerDownload } from "@/lib/export";
import type { CustomPlatformMap } from "@/lib/types";
import { PlusIcon, TrashIcon } from "./icons";

type CustomPlatformsProps = {
  onChange: () => void; // notify parent to refetch the platform picker
};

const field =
  "rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25";

export default function CustomPlatforms({ onChange }: CustomPlatformsProps) {
  const [platforms, setPlatforms] = useState<CustomPlatformMap>({});
  const [allCategories, setAllCategories] = useState<string[]>([]);
  const [category, setCategory] = useState("");
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importMsg, setImportMsg] = useState<string | null>(null);

  useEffect(() => {
    getCustomPlatforms().then(setPlatforms).catch(() => setError("Couldn't load custom platforms."));
    fetchPlatforms().then((p) => setAllCategories(p.categories || [])).catch(() => {});
  }, []);

  // Suggest all known categories (built-in + custom), deduped.
  const categorySuggestions = useMemo(
    () => Array.from(new Set([...allCategories, ...Object.keys(platforms)])).sort(),
    [allCategories, platforms],
  );

  const entries = Object.entries(platforms);
  const total = entries.reduce((n, [, items]) => n + Object.keys(items).length, 0);

  // Live preview of the {query} substitution.
  const preview = url.includes("{query}")
    ? url.replace("{query}", encodeURIComponent("acme"))
    : null;

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
      setPlatforms(await addCustomPlatform(category.trim(), name.trim(), url.trim()));
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
      setPlatforms(await removeCustomPlatform(cat, platform));
      onChange();
    } catch {
      setError("Failed to remove platform.");
    } finally {
      setBusy(false);
    }
  }

  function handleExport() {
    triggerDownload("custom_platforms.json", JSON.stringify(platforms, null, 2), "application/json");
  }

  async function handleImport() {
    setImportMsg(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(importText);
    } catch {
      setImportMsg("Invalid JSON.");
      return;
    }
    setBusy(true);
    try {
      const r = await importCustomPlatforms(parsed as CustomPlatformMap);
      setPlatforms(r.platforms);
      onChange();
      setImportMsg(`Added ${r.added}${r.skipped.length ? ` · skipped ${r.skipped.length}: ${r.skipped.slice(0, 3).join(", ")}${r.skipped.length > 3 ? "…" : ""}` : ""}`);
      if (r.added) setImportText("");
    } catch (e) {
      setImportMsg(e instanceof Error ? e.message : "Import failed.");
    } finally {
      setBusy(false);
    }
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) setImportText(await f.text());
  }

  return (
    <div className="animate-fade-in flex max-w-5xl flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Add form */}
        <form onSubmit={handleAdd} className="rounded-2xl border border-line bg-surface/70 p-5 shadow-card">
          <h3 className="text-sm font-semibold text-fg">Add custom platform</h3>
          <p className="mt-1 text-xs text-fg-muted">
            The URL template must contain{" "}
            <code className="rounded bg-canvas px-1 font-mono text-accent">{"{query}"}</code> where the target is substituted.
          </p>

          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Category
              <input className={field} list="all-categories" value={category} onChange={(e) => setCategory(e.target.value)} placeholder="web" required />
              <datalist id="all-categories">
                {categorySuggestions.map((c) => (
                  <option key={c} value={c} />
                ))}
              </datalist>
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Name
              <input className={field} value={name} onChange={(e) => setName(e.target.value)} placeholder="My Engine" required />
            </label>
          </div>
          <label className="mt-3 flex flex-col gap-1 text-xs text-fg-muted">
            URL template
            <input className={`${field} font-mono`} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/search?q={query}" required />
          </label>

          {preview && (
            <div className="mt-2 truncate rounded-lg border border-line-soft bg-canvas px-3 py-2 font-mono text-[11px] text-fg-muted" title={preview}>
              <span className="text-fg-faint">preview: </span>
              {preview}
            </div>
          )}

          {error && <p className="mt-3 text-sm text-danger">{error}</p>}

          <button type="submit" disabled={busy} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent-gradient shadow-glow px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-strong disabled:opacity-40">
            <PlusIcon className="h-4 w-4" />
            Add platform
          </button>
        </form>

        {/* Import / export */}
        <div className="rounded-2xl border border-line bg-surface/70 p-5 shadow-card">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-fg">Import / export</h3>
            <button type="button" onClick={handleExport} disabled={total === 0} className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent disabled:opacity-40">
              Export JSON
            </button>
          </div>
          <p className="mt-1 text-xs text-fg-muted">
            Bulk-add from a <code className="font-mono text-accent">{"{category: {name: url}}"}</code> JSON map. Invalid entries are skipped.
          </p>

          {!importOpen ? (
            <button type="button" onClick={() => setImportOpen(true)} className="mt-4 rounded-lg border border-line px-3 py-2 text-sm font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent">
              Import JSON…
            </button>
          ) : (
            <div className="mt-3 flex flex-col gap-2">
              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                rows={7}
                placeholder={'{\n  "web": {\n    "My Engine": "https://ex.com/?q={query}"\n  }\n}'}
                className={`${field} resize-y font-mono text-xs`}
              />
              <div className="flex flex-wrap items-center gap-2">
                <button type="button" onClick={handleImport} disabled={busy || !importText.trim()} className="rounded-lg bg-accent-gradient px-3 py-1.5 text-xs font-semibold text-white shadow-glow disabled:opacity-40">
                  Import
                </button>
                <label className="cursor-pointer rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent">
                  Upload .json
                  <input type="file" accept="application/json,.json" onChange={onFile} className="hidden" />
                </label>
                <button type="button" onClick={() => { setImportOpen(false); setImportMsg(null); }} className="text-xs text-fg-faint hover:text-fg">
                  Close
                </button>
                {importMsg && <span className="font-mono text-[11px] text-fg-faint">{importMsg}</span>}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Existing */}
      <div className="overflow-hidden rounded-2xl border border-line bg-surface/60 shadow-card">
        <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
          <span className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">User-added platforms</span>
          <span className="font-mono text-[11px] text-fg-faint">
            {total} across {entries.length} categor{entries.length === 1 ? "y" : "ies"}
          </span>
        </div>
        {entries.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-fg-muted">No custom platforms yet.</p>
        ) : (
          entries.map(([cat, items]) => (
            <div key={cat}>
              <div className="flex items-center gap-2.5 px-4 py-2">
                <span className="font-mono text-xs uppercase tracking-wider text-accent">{cat}</span>
                <span className="font-mono text-[10px] text-fg-faint">{Object.keys(items).length}</span>
                <span className="h-px flex-1 bg-line-soft" />
              </div>
              <div className="divide-y divide-line-soft/60 border-b border-line-soft">
                {Object.entries(items).map(([platform, tpl]) => (
                  <div key={platform} className="group flex items-center gap-3 px-4 py-2">
                    <span className="w-40 shrink-0 truncate text-sm text-fg">{platform}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg-muted" title={tpl}>{tpl}</span>
                    <button type="button" onClick={() => handleRemove(cat, platform)} disabled={busy} title="Remove" className="text-fg-faint transition-colors hover:text-danger disabled:opacity-40">
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
