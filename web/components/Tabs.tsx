"use client";

import type { ReactNode } from "react";

export type TabKey = "search" | "domain" | "custom" | "settings";

type Tab = {
  key: TabKey;
  label: string;
  icon: ReactNode;
};

type TabsProps = {
  tabs: Tab[];
  active: TabKey;
  onChange: (key: TabKey) => void;
};

export default function Tabs({ tabs, active, onChange }: TabsProps) {
  return (
    <div className="flex gap-1 border-b border-line-soft">
      {tabs.map((tab) => {
        const isActive = tab.key === active;
        return (
          <button
            key={tab.key}
            type="button"
            onClick={() => onChange(tab.key)}
            className={`flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              isActive
                ? "border-accent text-accent"
                : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            <span className="h-4 w-4">{tab.icon}</span>
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}
