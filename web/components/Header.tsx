import { EyeMark } from "./icons";

export default function Header() {
  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between border-b border-line-soft bg-rail/80 px-4 backdrop-blur-xl">
      <div className="flex items-center gap-3">
        <span className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-b from-accent/25 to-accent/5 text-accent ring-1 ring-inset ring-accent/30 shadow-[0_0_20px_-6px_var(--color-accent)]">
          <EyeMark className="h-5 w-5" />
        </span>
        <div className="leading-tight">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold tracking-[0.14em] text-fg">
              OSIRIS
            </span>
            <span className="rounded border border-line bg-surface px-1.5 py-px text-[10px] font-medium uppercase tracking-wider text-fg-faint">
              v1
            </span>
          </div>
          <span className="text-[11px] text-fg-muted">OSINT link engine</span>
        </div>
      </div>

      <div className="flex items-center gap-2 rounded-full border border-line bg-surface/70 px-3 py-1.5 backdrop-blur">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-live/60" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-live" />
        </span>
        <span className="font-mono text-[11px] text-fg-muted">
          api&nbsp;·&nbsp;localhost:8000
        </span>
      </div>
    </header>
  );
}
