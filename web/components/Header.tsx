import { EyeMark } from "./icons";

export default function Header() {
  return (
    <header className="sticky top-0 z-20 border-b border-line-soft bg-canvas/80 backdrop-blur">
      <div className="mx-auto flex h-14 w-full max-w-5xl items-center justify-between px-5">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-md border border-line bg-surface text-accent shadow-[0_0_18px_-6px_var(--color-accent)]">
            <EyeMark className="h-5 w-5" />
          </span>
          <div className="leading-tight">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-semibold tracking-[0.2em] text-fg">
                OSIRIS
              </span>
              <span className="rounded border border-line bg-surface px-1.5 py-px font-mono text-[10px] uppercase tracking-wider text-fg-faint">
                v1
              </span>
            </div>
            <span className="text-[11px] text-fg-muted">
              OSINT link engine
            </span>
          </div>
        </div>

        <div className="hidden items-center gap-2 sm:flex">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-live" />
          <span className="font-mono text-[11px] text-fg-muted">
            api&nbsp;·&nbsp;localhost:8000
          </span>
        </div>
      </div>
    </header>
  );
}
