"use client";

import { exportRows } from "@/lib/export";
import { DownloadIcon } from "../icons";

export default function ExportRows({
  rows,
  baseName,
}: {
  rows: Record<string, unknown>[];
  baseName: string;
}) {
  if (!rows.length) return null;
  const btn =
    "rounded-md border border-line bg-surface px-2.5 py-1 text-xs font-medium text-fg-muted transition-colors hover:text-fg";
  return (
    <div className="flex items-center gap-1.5">
      <DownloadIcon className="h-3.5 w-3.5 text-fg-faint" />
      <button type="button" className={btn} onClick={() => exportRows(rows, baseName, "csv")}>
        CSV
      </button>
      <button type="button" className={btn} onClick={() => exportRows(rows, baseName, "json")}>
        JSON
      </button>
    </div>
  );
}
