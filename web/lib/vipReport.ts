import type { VipScorecard } from "./types";
import { triggerDownload } from "./export";

function esc(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ] as string,
  );
}

const LEVEL_COLOR: Record<string, string> = {
  high: "#dc2626",
  medium: "#d97706",
  low: "#16a34a",
  unknown: "#6b7280",
};

function badge(level: string): string {
  const color = LEVEL_COLOR[level] ?? "#6b7280";
  return `<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#fff;background:${color}">${esc(level)}</span>`;
}

function scoreColor(score: number): string {
  if (score >= 70) return "#dc2626";
  if (score >= 40) return "#d97706";
  return "#16a34a";
}

function linkList(items: { label?: string; platform?: string; category?: string; url: string }[]): string {
  if (!items.length) return '<p class="muted">None.</p>';
  return (
    '<ul class="links">' +
    items
      .map((p) => {
        const label = p.label ?? `${p.platform ?? ""} · ${p.category ?? ""}`;
        return `<li><span>${esc(label)}</span><br><a href="${esc(p.url)}">${esc(p.url)}</a></li>`;
      })
      .join("") +
    "</ul>"
  );
}

/** JSON dump of the full scorecard. */
export function exportVipJson(sc: VipScorecard): void {
  const name = sc.profile.name || "vip";
  triggerDownload(
    `vip-${name}.json`,
    JSON.stringify(sc, null, 2),
    "application/json",
  );
}

/** Open a print-friendly HTML report in a new window (Save as PDF via print). */
export function openVipReport(sc: VipScorecard): void {
  const p = sc.profile;
  const profileRows = [
    ["Name", p.name],
    ["Aliases", p.aliases.join(", ")],
    ["Emails", p.emails.join(", ")],
    ["Handles", p.usernames.join(", ")],
    ["Company", p.company],
    ["Country", p.country],
  ]
    .filter(([, v]) => v)
    .map(
      ([k, v]) =>
        `<tr><th>${esc(k)}</th><td class="mono">${esc(v)}</td></tr>`,
    )
    .join("");

  const m = sc.presence.mention;
  const mentionBasis = !m.configured
    ? "mentions n/a"
    : m.error
      ? "mentions unavailable"
      : `mentions ${m.level}${m.has_infobox ? " (knowledge panel)" : ""}`;
  const dims = [
    ["Online presence", sc.levels.presence, `footprint ${sc.presence.resolved_count}/${sc.presence.checked_platforms} · ${mentionBasis}`],
    ["Service discoverability", sc.levels.discoverability, sc.discoverability.hibp_configured ? `${sc.discoverability.breach_count} breach hits across ${sc.discoverability.emails.length} email(s)` : "HIBP not configured — resolution signals only"],
    ["Geo-location risk", sc.levels.geo, p.country || "no country supplied"],
    ["Impersonations", sc.levels.impersonation, `${sc.impersonation.confirmed} confirmed`],
  ]
    .map(
      ([title, level, detail]) =>
        `<tr><td>${esc(title)}</td><td>${badge(level)}</td><td class="muted">${esc(detail)}</td></tr>`,
    )
    .join("");

  const profiles = sc.presence.profiles.length
    ? '<table><thead><tr><th>Platform</th><th>Handle</th><th>URL</th></tr></thead><tbody>' +
      sc.presence.profiles
        .map(
          (r) =>
            `<tr><td>${esc(r.platform)}</td><td class="mono">@${esc(r.username)}</td><td class="mono"><a href="${esc(r.url)}">${esc(r.url)}</a></td></tr>`,
        )
        .join("") +
      "</tbody></table>"
    : '<p class="muted">No profiles resolved (add handles).</p>';

  const breaches = sc.discoverability.emails.filter((e) => e.count > 0);
  const breachBlock = breaches.length
    ? '<table><thead><tr><th>Email</th><th>Breaches</th><th>Names</th></tr></thead><tbody>' +
      breaches
        .map(
          (e) =>
            `<tr><td class="mono">${esc(e.email)}</td><td>${e.count}</td><td class="muted">${esc(e.breaches.join(", "))}</td></tr>`,
        )
        .join("") +
      "</tbody></table>"
    : "";

  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>Osiris VIP Report — ${esc(p.name)}</title>
<style>
  body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#111;margin:40px;line-height:1.4;}
  h1{font-size:18px;margin:0 0 2px;} h2{font-size:15px;color:#374151;margin:0 0 4px;}
  h3{font-size:13px;margin:22px 0 8px;text-transform:uppercase;letter-spacing:.5px;color:#374151;border-bottom:1px solid #e5e7eb;padding-bottom:4px;}
  .meta{color:#6b7280;font-size:12px;margin-bottom:16px;}
  .score{font-size:44px;font-weight:700;line-height:1;color:${scoreColor(sc.overall_score)};}
  .scorewrap{display:flex;align-items:baseline;gap:10px;margin:12px 0 4px;}
  .scorewrap span{color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:.5px;}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:4px;}
  th,td{border:1px solid #d1d5db;padding:6px 8px;text-align:left;vertical-align:top;}
  th{background:#f3f4f6;white-space:nowrap;} .mono{font-family:ui-monospace,Menlo,monospace;word-break:break-all;}
  .muted{color:#6b7280;} .links{margin:0;padding-left:16px;font-size:12px;} .links li{margin-bottom:6px;}
  .disclaimer{margin-top:26px;font-size:10px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:8px;}
  a{color:#2563eb;} @media print{body{margin:12px;} a{color:#111;text-decoration:none;}}
</style></head><body>
  <h1>Osiris — VIP Exposure Report</h1>
  <h2>${esc(p.name)}${p.company ? ` · ${esc(p.company)}` : ""}</h2>
  <div class="meta">Generated ${esc(new Date().toLocaleString())}</div>

  <div class="scorewrap"><span class="score">${sc.overall_score}</span><span>overall exposure / 100</span></div>

  <h3>Risk dimensions</h3>
  <table><thead><tr><th>Dimension</th><th>Level</th><th>Basis</th></tr></thead><tbody>${dims}</tbody></table>

  <h3>Profile</h3>
  <table><tbody>${profileRows || '<tr><td class="muted">No details.</td></tr>'}</tbody></table>

  <h3>Resolved profiles</h3>
  ${profiles}

  ${breachBlock ? `<h3>Breach exposure</h3>${breachBlock}` : ""}

  <h3>Investigator pivots — presence &amp; handle discovery</h3>
  ${linkList(sc.pivots.social)}
  <h3>Investigator pivots — family / relatives</h3>
  ${linkList(sc.pivots.family)}
  <h3>Investigator pivots — business / associates</h3>
  ${linkList(sc.pivots.business)}
  <h3>Investigator pivots — geo / location</h3>
  ${linkList(sc.pivots.geo)}

  <div class="disclaimer">Defensive exposure assessment for authorized executive-protection / digital-risk-protection use.
  Levels are heuristics: handle resolution indicates a handle exists on a platform, not identity; the geo tier is a coarse,
  overridable default. Verify via the pivots before acting.</div>
  <script>window.onload=function(){window.print();}</script>
</body></html>`;

  const win = window.open("", "_blank");
  if (win) {
    win.document.write(html);
    win.document.close();
  }
}
