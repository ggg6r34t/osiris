"use client";

import { useEffect, useState } from "react";
import {
  getAlertChannels,
  getIntegrations,
  getSettings,
  saveSettings,
  testAlerts,
} from "@/lib/api";
import type { Integrations, Settings } from "@/lib/types";
import { CheckIcon } from "./icons";

const field =
  "rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent focus:ring-2 focus:ring-accent/25";

function Card({
  title,
  desc,
  children,
  className = "",
}: {
  title: string;
  desc?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-2xl border border-line bg-surface/70 p-5 shadow-card ${className}`}>
      <h3 className="text-sm font-semibold text-fg">{title}</h3>
      {desc && <p className="mt-1 text-xs text-fg-muted">{desc}</p>}
      <div className="mt-4">{children}</div>
    </div>
  );
}

function Badge({ on, onLabel = "on", offLabel = "off" }: { on: boolean; onLabel?: string; offLabel?: string }) {
  return (
    <span
      className={`rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider ${
        on ? "border-live/40 bg-live/10 text-live" : "border-line bg-surface-2 text-fg-faint"
      }`}
    >
      {on ? onLabel : offLabel}
    </span>
  );
}

function StatusRow({ label, on, hint }: { label: string; on: boolean; hint?: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 text-sm">
      <span className="text-fg-muted">{label}</span>
      <Badge on={on} onLabel="configured" offLabel="not set" />
      {hint && <span className="sr-only">{hint}</span>}
    </div>
  );
}

function NetworkCard() {
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

  if (!settings)
    return (
      <Card title="Network" className="lg:col-span-2">
        <p className="text-sm text-fg-muted">{error ?? "Loading…"}</p>
      </Card>
    );

  return (
    <Card
      title="Network"
      desc="Applied to link-checking and domain-intel requests. Stored on the running API."
      className="lg:col-span-2"
    >
      <div className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            User-Agent
            <input className={field} value={settings.user_agent} onChange={(e) => update("user_agent", e.target.value)} placeholder="Osiris/1.0" />
          </label>
          <div className="grid grid-cols-2 gap-4">
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Timeout (s)
              <input type="number" min={1} className={field} value={settings.request_timeout} onChange={(e) => update("request_timeout", parseFloat(e.target.value) || 0)} />
            </label>
            <label className="flex flex-col gap-1 text-xs text-fg-muted">
              Rate limit (req/s)
              <input type="number" min={0} className={field} value={settings.rate_limit} onChange={(e) => update("rate_limit", parseFloat(e.target.value) || 0)} />
            </label>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            HTTP proxy
            <input className={field} value={tor ? "socks5h://127.0.0.1:9050" : settings.http_proxy} disabled={tor} onChange={(e) => update("http_proxy", e.target.value)} placeholder="http://127.0.0.1:8080" />
          </label>
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            HTTPS proxy
            <input className={field} value={tor ? "socks5h://127.0.0.1:9050" : settings.https_proxy} disabled={tor} onChange={(e) => update("https_proxy", e.target.value)} placeholder="http://127.0.0.1:8080" />
          </label>
        </div>

        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <label className="flex items-center gap-2 text-sm text-fg-muted">
            <input type="checkbox" checked={tor} onChange={(e) => { setTor(e.target.checked); setSaved(false); }} className="accent-[var(--color-accent)]" />
            Route through Tor
          </label>
          <label className="flex items-center gap-2 text-sm text-fg-muted">
            <input type="checkbox" checked={!settings.verify_tls} onChange={(e) => update("verify_tls", !e.target.checked)} className="accent-[var(--color-accent)]" />
            Disable TLS verification (insecure)
          </label>
        </div>

        {error && <p className="text-sm text-danger">{error}</p>}
        <div className="flex items-center gap-3">
          <button type="button" onClick={handleSave} disabled={saving} className="inline-flex items-center gap-2 rounded-lg bg-accent-gradient shadow-glow px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-accent-strong disabled:opacity-40">
            {saving ? "Saving…" : "Save network settings"}
          </button>
          {saved && (
            <span className="flex items-center gap-1.5 text-sm text-live">
              <CheckIcon className="h-4 w-4" /> Saved
            </span>
          )}
        </div>
      </div>
    </Card>
  );
}

function AlertingCard({ data, onRefresh }: { data: Integrations; onRefresh: () => void }) {
  const [testing, setTesting] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const configured = data.alerting.telegram || data.alerting.webhook;

  async function sendTest() {
    setTesting(true);
    setMsg(null);
    try {
      const r = await testAlerts();
      setMsg(
        !r.configured
          ? "Not configured"
          : Object.entries(r.results)
              .filter(([, v]) => !v.skipped)
              .map(([k, v]) => `${k}: ${v.ok ? "sent" : v.error || `HTTP ${v.status}`}`)
              .join(" · ") || "Sent",
      );
      onRefresh();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Test failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <Card title="Alerting" desc="Notifications for new monitor findings & takedown changes.">
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between text-sm">
          <span className="text-fg-muted">Telegram</span>
          <Badge on={data.alerting.telegram} />
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-fg-muted">Webhook</span>
          <Badge on={data.alerting.webhook} />
        </div>
        <div className="mt-2 flex items-center gap-3">
          <button
            type="button"
            onClick={sendTest}
            disabled={testing || !configured}
            className="rounded-md border border-line px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:border-accent hover:text-accent disabled:opacity-40"
          >
            {testing ? "Sending…" : "Send test"}
          </button>
          {msg && <span className="font-mono text-[11px] text-fg-faint">{msg}</span>}
        </div>
        <p className="mt-1 text-[11px] text-fg-faint">
          Configure with OSIRIS_TELEGRAM_BOT_TOKEN / OSIRIS_TELEGRAM_CHAT_ID or OSIRIS_ALERT_WEBHOOK_URL in .env.
        </p>
      </div>
    </Card>
  );
}

export default function SettingsPanel() {
  const [integrations, setIntegrations] = useState<Integrations | null>(null);
  const [channels, setChannels] = useState<{ telegram: boolean; webhook: boolean } | null>(null);

  const load = () => {
    getIntegrations().then(setIntegrations).catch(() => setIntegrations(null));
    getAlertChannels().then(setChannels).catch(() => {});
  };
  useEffect(() => load(), []);

  return (
    <div className="animate-fade-in flex max-w-5xl flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <NetworkCard />

        {integrations && (
          <>
            <Card title="Integrations & API keys" desc="Status only — secret values live in .env, never shown here.">
              <div className="divide-y divide-line-soft/60">
                {Object.entries(integrations.keys).map(([k, v]) => (
                  <StatusRow key={k} label={k} on={v} />
                ))}
              </div>
            </Card>

            <AlertingCard
              data={{ ...integrations, alerting: channels ?? integrations.alerting }}
              onRefresh={load}
            />

            <Card title="Security" desc="Protections for server-side fetches.">
              <div className="flex flex-col gap-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-fg-muted">SSRF guard (block private/metadata targets)</span>
                  <Badge on={integrations.features.ssrf_guard} onLabel="active" offLabel="off" />
                </div>
                <p className="text-[11px] text-fg-faint">
                  URL Analyze / Enrich / Abuse Router / screenshots refuse non-public hosts unless
                  OSIRIS_ALLOW_PRIVATE_TARGETS=true.
                </p>
              </div>
            </Card>

            <Card title="System" desc="Runtime & local data.">
              <div className="flex flex-col gap-2 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-fg-muted">Screenshots (Playwright)</span>
                  <Badge on={integrations.features.screenshots} onLabel="available" offLabel="not installed" />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-fg-muted">Version</span>
                  <span className="font-mono text-xs text-fg">{integrations.version}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-fg-muted">Local database</span>
                  <span className="font-mono text-xs text-fg">{integrations.storage.db_path}</span>
                </div>
                <div className="mt-1 flex gap-4 font-mono text-xs text-fg-faint">
                  <span>{integrations.storage.cases} cases</span>
                  <span>{integrations.storage.takedowns} takedowns</span>
                  <span>{integrations.storage.history} runs</span>
                </div>
              </div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
