"use client";

import { useEffect, useState } from "react";
import { getSettings, saveSettings } from "@/lib/api";
import type { Settings } from "@/lib/types";
import { CheckIcon } from "./icons";

export default function SettingsPanel() {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [tor, setTor] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSettings()
      .then((s) => {
        setSettings(s);
        setTor(s.http_proxy.startsWith("socks5h://127.0.0.1:9050"));
      })
      .catch(() => setError("Couldn't load settings from the API."));
  }, []);

  function update<K extends keyof Settings>(key: K, value: Settings[K]) {
    setSettings((s) => (s ? { ...s, [key]: value } : s));
    setSaved(false);
  }

  async function handleSave() {
    if (!settings) return;
    setSaving(true);
    setError(null);
    try {
      const next = await saveSettings({ ...settings, tor });
      setSettings(next);
      setTor(next.http_proxy.startsWith("socks5h://127.0.0.1:9050"));
      setSaved(true);
    } catch {
      setError("Failed to save settings.");
    } finally {
      setSaving(false);
    }
  }

  if (!settings) {
    return (
      <div className="rounded-xl border border-line bg-surface/60 px-4 py-12 text-center text-sm text-fg-muted">
        {error ?? "Loading settings…"}
      </div>
    );
  }

  const field =
    "rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25";

  return (
    <div className="animate-fade-in max-w-2xl rounded-2xl border border-line bg-surface/70 p-6 shadow-card">
      <h2 className="text-base font-medium text-fg">Network settings</h2>
      <p className="mt-1 text-sm text-fg-muted">
        Applied to link-checking and domain-intel requests. Stored on the
        running API instance.
      </p>

      <div className="mt-5 flex flex-col gap-4">
        <label className="flex flex-col gap-1 text-xs text-fg-muted">
          User-Agent
          <input
            className={field}
            value={settings.user_agent}
            onChange={(e) => update("user_agent", e.target.value)}
            placeholder="Osiris/1.0"
          />
        </label>

        <div className="grid grid-cols-2 gap-4">
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Request timeout (s)
            <input
              type="number"
              min={1}
              className={field}
              value={settings.request_timeout}
              onChange={(e) =>
                update("request_timeout", parseFloat(e.target.value) || 0)
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Rate limit (req/s, 0 = none)
            <input
              type="number"
              min={0}
              className={field}
              value={settings.rate_limit}
              onChange={(e) =>
                update("rate_limit", parseFloat(e.target.value) || 0)
              }
            />
          </label>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            HTTP proxy
            <input
              className={field}
              value={tor ? "socks5h://127.0.0.1:9050" : settings.http_proxy}
              disabled={tor}
              onChange={(e) => update("http_proxy", e.target.value)}
              placeholder="http://127.0.0.1:8080"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            HTTPS proxy
            <input
              className={field}
              value={tor ? "socks5h://127.0.0.1:9050" : settings.https_proxy}
              disabled={tor}
              onChange={(e) => update("https_proxy", e.target.value)}
              placeholder="http://127.0.0.1:8080"
            />
          </label>
        </div>

        <label className="flex items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            checked={tor}
            onChange={(e) => {
              setTor(e.target.checked);
              setSaved(false);
            }}
            className="accent-[var(--color-accent)]"
          />
          Route through Tor (socks5h://127.0.0.1:9050)
        </label>

        <label className="flex items-center gap-2 text-sm text-fg-muted">
          <input
            type="checkbox"
            checked={!settings.verify_tls}
            onChange={(e) => update("verify_tls", !e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          Disable TLS verification (insecure)
        </label>
      </div>

      {error && <p className="mt-4 text-sm text-danger">{error}</p>}

      <div className="mt-5 flex items-center gap-3">
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 rounded-lg bg-accent-gradient shadow-glow px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-strong disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save settings"}
        </button>
        {saved && (
          <span className="flex items-center gap-1.5 text-sm text-live">
            <CheckIcon className="h-4 w-4" /> Saved
          </span>
        )}
      </div>
    </div>
  );
}
