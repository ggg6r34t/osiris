"use client";

import type { ReactNode } from "react";

export type TabKey = "search" | "domain" | "custom" | "settings";

export type NavItem = {
  key: TabKey;
  label: string;
  icon: ReactNode;
};

type SidebarProps = {
  items: NavItem[];
  active: TabKey;
  onChange: (key: TabKey) => void;
};

export default function Sidebar({ items, active, onChange }: SidebarProps) {
  return (
    <nav className="flex w-[88px] shrink-0 flex-col gap-1 border-r border-line-soft bg-rail py-3">
      {items.map((item) => {
        const isActive = item.key === active;
        return (
          <button
            key={item.key}
            type="button"
            onClick={() => onChange(item.key)}
            title={item.label}
            className={`relative mx-2 flex flex-col items-center gap-1.5 rounded-lg px-1 py-3 text-center transition-colors ${
              isActive
                ? "bg-accent/12 text-accent"
                : "text-fg-faint hover:bg-white/[0.03] hover:text-fg"
            }`}
          >
            {isActive && (
              <span className="absolute left-0 top-1/2 h-6 w-0.5 -translate-y-1/2 rounded-r bg-accent" />
            )}
            <span className="h-5 w-5">{item.icon}</span>
            <span className="text-[10px] font-medium leading-tight">
              {item.label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
