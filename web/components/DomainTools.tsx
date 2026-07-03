"use client";

import { useState } from "react";
import EnrichView from "./domain/EnrichView";
import DomainMatchView from "./domain/DomainMatchView";
import DnstwistView from "./domain/DnstwistView";
import CloneDetectView from "./domain/CloneDetectView";
import DeepSearchView from "./domain/DeepSearchView";
import { PhishingDorksView, TextCloneView } from "./domain/LinkToolView";

type ToolKey =
  | "enrich"
  | "domain-match"
  | "dnstwist"
  | "clone-detect"
  | "text-clone"
  | "phishing-dorks"
  | "deep-search";

const TOOLS: { key: ToolKey; label: string; blurb: string }[] = [
  { key: "enrich", label: "Enrich", blurb: "WHOIS · DNS · hosting · SSL · risk" },
  { key: "domain-match", label: "Domain Match", blurb: "Registered lookalikes" },
  { key: "dnstwist", label: "DNSTwist", blurb: "Permutation scan" },
  { key: "clone-detect", label: "Clone Detect", blurb: "Byte-identical clones" },
  { key: "text-clone", label: "Text Clone", blurb: "Copycat text dorks" },
  { key: "phishing-dorks", label: "Phishing Dorks", blurb: "Keyword dorks" },
  { key: "deep-search", label: "Deep Search", blurb: "Everything combined" },
];

export default function DomainTools() {
  const [tool, setTool] = useState<ToolKey>("enrich");
  const active = TOOLS.find((t) => t.key === tool)!;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap gap-1.5">
        {TOOLS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTool(t.key)}
            className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
              t.key === tool
                ? "border-accent/40 bg-accent/10 text-accent"
                : "border-line bg-surface text-fg-muted hover:text-fg"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <p className="-mt-2 font-mono text-xs text-fg-faint">{active.blurb}</p>

      {tool === "enrich" && <EnrichView />}
      {tool === "domain-match" && <DomainMatchView />}
      {tool === "dnstwist" && <DnstwistView />}
      {tool === "clone-detect" && <CloneDetectView />}
      {tool === "text-clone" && <TextCloneView />}
      {tool === "phishing-dorks" && <PhishingDorksView />}
      {tool === "deep-search" && <DeepSearchView />}
    </div>
  );
}
