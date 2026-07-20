"use client";

import type { ReactNode } from "react";

export type TabKey = "search" | "domain" | "vip" | "cases" | "custom" | "settings";

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
    <nav className="flex w-[92px] shrink-0 flex-col gap-1.5 border-r border-line-soft bg-rail py-4">
      {items.map((item) => {
        const isActive = item.key === active;
        return (
          <button
            key={item.key}
            type="button"
            onClick={() => onChange(item.key)}
            title={item.label}
            className={`group relative mx-2 flex flex-col items-center gap-1.5 rounded-xl px-1 py-3 text-center transition-all duration-200 ${
              isActive
                ? "bg-gradient-to-b from-accent/18 to-accent/5 text-accent ring-1 ring-inset ring-accent/25"
                : "text-fg-faint hover:bg-white/[0.04] hover:text-fg"
            }`}
          >
            <span
              className={`absolute left-0 top-1/2 w-[3px] -translate-y-1/2 rounded-r-full bg-accent transition-all duration-200 ${
                isActive
                  ? "h-7 opacity-100 shadow-[0_0_10px_0_var(--color-accent)]"
                  : "h-0 opacity-0"
              }`}
            />
            <span
              className={`h-5 w-5 transition-transform duration-200 ${
                isActive ? "" : "group-hover:scale-110"
              }`}
            >
              {item.icon}
            </span>
            <span className="text-[10px] font-medium leading-tight">
              {item.label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
