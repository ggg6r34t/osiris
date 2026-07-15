import { EyeMark } from "./icons";

export default function Header() {
  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-line-soft bg-rail px-4">
      <div className="flex items-center gap-3">
        <span className="flex h-8 w-8 items-center justify-center rounded-md bg-accent/15 text-accent">
          <EyeMark className="h-5 w-5" />
        </span>
        <div className="leading-tight">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold tracking-wide text-fg">
              OSIRIS
            </span>
            <span className="rounded border border-line bg-surface px-1.5 py-px text-[10px] font-medium uppercase tracking-wider text-fg-faint">
              v1
            </span>
          </div>
          <span className="text-[11px] text-fg-muted">OSINT link engine</span>
        </div>
      </div>

      <div className="flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1.5">
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-live" />
        <span className="font-mono text-[11px] text-fg-muted">
          api&nbsp;·&nbsp;localhost:8000
        </span>
      </div>
    </header>
  );
}
