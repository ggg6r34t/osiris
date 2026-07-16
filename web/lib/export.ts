import type { SearchResult } from "./types";

function csvField(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function toCsv(results: SearchResult[]): string {
  const hasTarget = results.some((r) => r.target);
  const hasScore = results.some((r) => r.score !== undefined);

  const headers = ["platform", "category", "url"];
  if (hasTarget) headers.push("target");
  if (hasScore) headers.push("score", "label", "reasons");

  const rows = [headers.join(",")];
  for (const r of results) {
    const cells = [r.platform, r.category, r.url];
    if (hasTarget) cells.push(r.target ?? "");
    if (hasScore) {
      cells.push(
        r.score !== undefined ? String(r.score) : "",
        r.label ?? "",
        (r.reasons ?? []).join("; "),
      );
    }
    rows.push(cells.map(csvField).join(","));
  }
  return rows.join("\n");
}

export function toJson(results: SearchResult[]): string {
  return JSON.stringify(results, null, 2);
}

export function toTxt(results: SearchResult[]): string {
  return results
    .map((r) => `[${r.category}] ${r.platform}: ${r.url}`)
    .join("\n");
}

/** Generic CSV for arbitrary flat row objects (union of keys as columns). */
export function rowsToCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "";
  const headers: string[] = [];
  for (const row of rows) {
    for (const k of Object.keys(row)) if (!headers.includes(k)) headers.push(k);
  }
  const cell = (v: unknown) =>
    csvField(v === null || v === undefined ? "" : String(v));
  return [
    headers.join(","),
    ...rows.map((r) => headers.map((h) => cell(r[h])).join(",")),
  ].join("\n");
}

/** Download arbitrary rows as CSV or JSON with a base filename. */
export function exportRows(
  rows: Record<string, unknown>[],
  baseName: string,
  fmt: "csv" | "json",
): void {
  if (fmt === "csv") {
    triggerDownload(`${baseName}.csv`, rowsToCsv(rows), "text/csv");
  } else {
    triggerDownload(
      `${baseName}.json`,
      JSON.stringify(rows, null, 2),
      "application/json",
    );
  }
}

export function triggerDownload(
  filename: string,
  content: string,
  mimeType: string,
): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
