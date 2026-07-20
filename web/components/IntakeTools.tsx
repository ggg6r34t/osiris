"use client";

import { useState } from "react";
import IocView from "./intake/IocView";
import EmailTriageView from "./intake/EmailTriageView";

type ToolKey = "ioc" | "email";

const TOOLS: { key: ToolKey; label: string; blurb: string }[] = [
  { key: "ioc", label: "IOC Extract", blurb: "Paste a report → refanged indicators → STIX / MISP" },
  { key: "email", label: "Email Triage", blurb: "Paste/upload .eml → auth, spoofing flags, origin IP, IOCs" },
];

export default function IntakeTools() {
  const [tool, setTool] = useState<ToolKey>("ioc");
  const active = TOOLS.find((t) => t.key === tool)!;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-1.5">
        {TOOLS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTool(t.key)}
            className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-all duration-150 ${
              t.key === tool
                ? "border-accent/40 bg-gradient-to-b from-accent/20 to-accent/5 text-accent ring-1 ring-inset ring-accent/20"
                : "border-line bg-surface text-fg-muted hover:border-line hover:bg-surface-2 hover:text-fg"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <p className="-mt-2 font-mono text-xs text-fg-faint">{active.blurb}</p>

      {tool === "ioc" && <IocView />}
      {tool === "email" && <EmailTriageView />}
    </div>
  );
}
