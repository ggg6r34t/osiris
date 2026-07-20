import type { CaseDetail, CaseItem, IocSet } from "./types";
import { exportIocs } from "./api";
import { exportRows, triggerDownload } from "./export";

function indicator(item: CaseItem): string {
  const d = item.data ?? {};
  const v = (d.domain ?? d.ip ?? "") as unknown;
  return typeof v === "string" ? v : "";
}

function esc(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ] as string,
  );
}

function itemRows(c: CaseDetail): Record<string, unknown>[] {
  return c.items.map((it) => ({
    kind: it.kind,
    indicator: indicator(it),
    status: it.status,
    note: it.note,
    added: new Date(it.ts * 1000).toISOString(),
    data: JSON.stringify(it.data),
  }));
}

export function exportCaseCsv(c: CaseDetail): void {
  exportRows(itemRows(c), `case-${c.name}`, "csv");
}

export function exportCaseJson(c: CaseDetail): void {
  triggerDownload(
    `case-${c.name}.json`,
    JSON.stringify(c, null, 2),
    "application/json",
  );
}

/** Newline-delimited unique indicators (domains/IPs) for IOC ingestion. */
export function exportCaseIocs(c: CaseDetail): void {
  const set = new Set<string>();
  for (const it of c.items) {
    const ind = indicator(it).trim();
    if (ind) set.add(ind);
  }
  triggerDownload(
    `iocs-${c.name}.txt`,
    [...set].join("\n"),
    "text/plain",
  );
}

function isIp(v: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) || v.includes(":");
}

/** Collect domain/IP indicators from a case's items into an IocSet. */
function caseIocSet(c: CaseDetail): IocSet {
  const domains = new Set<string>();
  const ips = new Set<string>();
  const add = (v: unknown) => {
    if (typeof v !== "string" || !v.trim()) return;
    (isIp(v.trim()) ? ips : domains).add(v.trim());
  };
  for (const it of c.items) {
    const d = (it.data ?? {}) as Record<string, unknown>;
    add(d.domain);
    add(d.ip);
    if (Array.isArray(d.indicators)) d.indicators.forEach(add);
  }
  return {
    domains: [...domains],
    ips: [...ips],
    urls: [],
    emails: [],
    hashes: { md5: [], sha1: [], sha256: [] },
    cves: [],
  };
}

/** Export a case's indicators as a STIX 2.1 bundle or MISP event JSON. */
export async function exportCaseStix(c: CaseDetail): Promise<void> {
  const doc = await exportIocs({ iocs: caseIocSet(c), format: "stix" });
  triggerDownload(`case-${c.name}.stix.json`, JSON.stringify(doc, null, 2), "application/json");
}

export async function exportCaseMisp(c: CaseDetail): Promise<void> {
  const doc = await exportIocs({ iocs: caseIocSet(c), format: "misp", info: `Osiris case: ${c.name}` });
  triggerDownload(`case-${c.name}.misp.json`, JSON.stringify(doc, null, 2), "application/json");
}

/** Open a print-friendly HTML report in a new window (Save as PDF via print). */
export function openCaseReport(c: CaseDetail): void {
  const rows = c.items
    .map(
      (it) =>
        `<tr><td>${esc(it.kind)}</td><td class="mono">${esc(indicator(it))}</td>` +
        `<td>${esc(it.status)}</td><td>${esc(it.note)}</td>` +
        `<td>${esc(new Date(it.ts * 1000).toLocaleString())}</td></tr>`,
    )
    .join("");

  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>Osiris Case — ${esc(c.name)}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#111;margin:40px;}
  h1{font-size:18px;margin:0 0 2px;} h2{font-size:15px;color:#374151;margin:0 0 12px;}
  .meta{color:#6b7280;font-size:12px;margin-bottom:20px;}
  table{border-collapse:collapse;width:100%;font-size:12px;}
  th,td{border:1px solid #d1d5db;padding:6px 8px;text-align:left;vertical-align:top;}
  th{background:#f3f4f6;} .mono{font-family:ui-monospace,Menlo,monospace;}
  @media print{body{margin:12px;}}
</style></head><body>
  <h1>Osiris — Case Report</h1>
  <h2>${esc(c.name)}</h2>
  <div class="meta">Generated ${esc(new Date().toLocaleString())} · ${c.items.length} item(s)${
    c.note ? ` · ${esc(c.note)}` : ""
  }</div>
  <table><thead><tr><th>Kind</th><th>Indicator</th><th>Status</th><th>Note</th><th>Added</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="5">No items.</td></tr>'}</tbody></table>
  <script>window.onload=function(){window.print();}</script>
</body></html>`;

  const win = window.open("", "_blank");
  if (win) {
    win.document.write(html);
    win.document.close();
  }
}
