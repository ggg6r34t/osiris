"use client";

import { useCallback, useState, type ReactNode } from "react";
import { AlertIcon, BoltIcon } from "../icons";

export function useTool<T>() {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(async (fn: () => Promise<T>) => {
    setLoading(true);
    setError(null);
    try {
      setData(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  return { data, loading, error, run, ran: data !== null || error !== null };
}

export function RunBar({
  value,
  onChange,
  onRun,
  loading,
  placeholder,
  button = "Run",
  multiline = false,
  hint,
}: {
  value: string;
  onChange: (v: string) => void;
  onRun: () => void;
  loading: boolean;
  placeholder: string;
  button?: string;
  multiline?: boolean;
  hint?: string;
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-col gap-2.5 sm:flex-row">
        {multiline ? (
          <textarea
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={placeholder}
            rows={3}
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) onRun();
            }}
            className="flex-1 resize-y rounded-lg border border-line bg-canvas px-3 py-2.5 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
          />
        ) : (
          <input
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && onRun()}
            placeholder={placeholder}
            className="flex-1 rounded-lg border border-line bg-canvas px-3 py-2.5 text-[15px] text-fg outline-none transition-colors placeholder:text-fg-faint focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
          />
        )}
        <button
          type="button"
          onClick={onRun}
          disabled={loading || !value.trim()}
          className="inline-flex h-[46px] items-center justify-center gap-2 self-start rounded-lg bg-accent px-5 text-sm font-semibold text-canvas transition-all hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? (
            <>
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-canvas/40 border-t-canvas" />
              Running
            </>
          ) : (
            <>
              <BoltIcon className="h-4 w-4" />
              {button}
            </>
          )}
        </button>
      </div>
      {hint && <p className="text-xs text-fg-faint">{hint}</p>}
    </div>
  );
}

export function ToolError({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="animate-fade-in flex items-start gap-3 rounded-lg border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-danger"
    >
      <AlertIcon className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{message}</span>
    </div>
  );
}

export function ToolLoading({ label }: { label: string }) {
  return (
    <div className="animate-fade-in flex items-center justify-center gap-3 rounded-xl border border-line bg-surface/40 px-4 py-12 text-sm text-fg-muted">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-fg-faint/40 border-t-fg-muted" />
      {label}
    </div>
  );
}

export function Card({
  title,
  right,
  children,
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface/60">
      <div className="flex items-center justify-between border-b border-line-soft px-4 py-2.5">
        <span className="font-mono text-[11px] uppercase tracking-wider text-accent">
          {title}
        </span>
        {right}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

export function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex gap-3 py-1 text-sm">
      <span className="w-32 shrink-0 text-fg-muted">{k}</span>
      <span className="min-w-0 flex-1 break-words text-fg">
        {v === null || v === undefined || v === "" ? (
          <span className="text-fg-faint">—</span>
        ) : (
          v
        )}
      </span>
    </div>
  );
}

export function RiskMeter({ score }: { score: number }) {
  const level =
    score >= 70 ? "critical" : score >= 40 ? "high" : score >= 20 ? "medium" : "low";
  const color =
    level === "critical" || level === "high"
      ? "var(--color-danger)"
      : level === "medium"
        ? "#fbbf24"
        : "var(--color-live)";
  return (
    <div className="flex items-center gap-4 rounded-xl border border-line bg-surface/60 p-4">
      <div className="flex flex-col">
        <span className="font-mono text-3xl font-semibold" style={{ color }}>
          {score}
        </span>
        <span className="text-[11px] uppercase tracking-wider text-fg-faint">
          risk / 100
        </span>
      </div>
      <div className="flex-1">
        <div className="h-2 overflow-hidden rounded-full bg-line">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${Math.min(100, Math.max(0, score))}%`, background: color }}
          />
        </div>
        <span
          className="mt-1.5 inline-block font-mono text-xs uppercase tracking-wider"
          style={{ color }}
        >
          {level}
        </span>
      </div>
    </div>
  );
}
