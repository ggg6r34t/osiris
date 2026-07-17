"use client";

import { useState } from "react";
import EnrichView from "./domain/EnrichView";
import DomainMatchView from "./domain/DomainMatchView";
import DnstwistView from "./domain/DnstwistView";
import CloneDetectView from "./domain/CloneDetectView";
import DeepSearchView from "./domain/DeepSearchView";
import BrandAbuseView from "./domain/BrandAbuseView";
import IpPivotView from "./domain/IpPivotView";
import { PhishingDorksView, TextCloneView } from "./domain/LinkToolView";

type ToolKey =
  | "enrich"
  | "ip-pivot"
  | "domain-match"
  | "dnstwist"
  | "clone-detect"
  | "brand-abuse"
  | "text-clone"
  | "phishing-dorks"
  | "deep-search";

const TOOLS: { key: ToolKey; label: string; blurb: string }[] = [
  { key: "enrich", label: "Enrich", blurb: "WHOIS · DNS · hosting · SSL · risk" },
  { key: "ip-pivot", label: "IP Pivot", blurb: "Reverse-IP · co-hosted domains" },
  { key: "domain-match", label: "Domain Match", blurb: "Registered lookalikes" },
  { key: "dnstwist", label: "DNSTwist", blurb: "Permutation scan" },
  { key: "clone-detect", label: "Clone Detect", blurb: "Byte-identical clones" },
  { key: "brand-abuse", label: "Brand Abuse (regex)", blurb: "Panda regex dataset search" },
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

      {tool === "enrich" && <EnrichView />}
      {tool === "ip-pivot" && <IpPivotView />}
      {tool === "domain-match" && <DomainMatchView />}
      {tool === "dnstwist" && <DnstwistView />}
      {tool === "clone-detect" && <CloneDetectView />}
      {tool === "brand-abuse" && <BrandAbuseView />}
      {tool === "text-clone" && <TextCloneView />}
      {tool === "phishing-dorks" && <PhishingDorksView />}
      {tool === "deep-search" && <DeepSearchView />}
    </div>
  );
}
