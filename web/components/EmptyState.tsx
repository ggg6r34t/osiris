import { EyeMark } from "./icons";

export default function EmptyState() {
  return (
    <div className="animate-fade-in flex flex-col items-center gap-4 rounded-xl border border-dashed border-line bg-surface/30 px-6 py-14 text-center">
      <span className="flex h-14 w-14 items-center justify-center rounded-full border border-line bg-surface text-accent/70 shadow-[0_0_40px_-12px_var(--color-accent)]">
        <EyeMark className="h-8 w-8" />
      </span>
      <div className="max-w-md">
        <h2 className="text-base font-medium text-fg">
          Enter a target to generate search links
        </h2>
        <p className="mt-1.5 text-sm text-fg-muted">
          Osiris builds ready-to-open OSINT search URLs across categorized
          platforms. It generates links — it does not crawl or scrape the sites
          themselves.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-2 font-mono text-xs text-fg-faint">
        <span className="rounded border border-line-soft bg-canvas px-2 py-1">
          social_networks
        </span>
        <span className="rounded border border-line-soft bg-canvas px-2 py-1">
          marketplace
        </span>
        <span className="rounded border border-line-soft bg-canvas px-2 py-1">
          phishing_detection
        </span>
        <span className="rounded border border-line-soft bg-canvas px-2 py-1">
          cyber_intel
        </span>
        <span className="text-fg-faint">+ more</span>
      </div>
    </div>
  );
}
