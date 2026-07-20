import type {
  AbuseRouteResult,
  AlertChannels,
  AlertTestResult,
  BrandAbuseResponse,
  BulkEnrichResponse,
  GenerateRegexResponse,
  RegexLevel,
  CheckResult,
  CloneDetectResult,
  CaseDetail,
  CaseSummary,
  CustomPlatformMap,
  DeepSearchResponse,
  EmailAnalysis,
  HistoryEntry,
  IocExtractResult,
  IocSet,
  Metrics,
  DnstwistEntry,
  DomainMatch,
  EnrichResult,
  IpPivotResult,
  MonitorReport,
  PlatformsResponse,
  ReputationResult,
  SearchOptions,
  SearchResponse,
  SearchResult,
  Settings,
  Takedown,
  TakedownEmail,
  UrlAnalysis,
  VipInput,
  VipScorecard,
  WatchTarget,
} from "./types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 240_000; // hard client-side cap so the UI never hangs

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      ...init,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") {
      throw new Error("Request timed out — the upstream sources were too slow.");
    }
    throw new Error(
      "Couldn't reach the Osiris API. Is the backend running on localhost:8000?",
    );
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    let detail = "";
    try {
      detail = (await res.json())?.detail ?? "";
    } catch {
      /* ignore */
    }
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export function fetchPlatforms(): Promise<PlatformsResponse> {
  return jsonFetch<PlatformsResponse>("/api/platforms");
}

export function runSearch(
  targets: string[],
  platforms: string[],
  options: SearchOptions,
): Promise<SearchResponse> {
  return jsonFetch<SearchResponse>("/api/search", {
    method: "POST",
    body: JSON.stringify({
      targets,
      platforms,
      exclude_platforms: options.excludePlatforms,
      exclude_categories: options.excludeCategories,
      fuzzy: options.fuzzy,
      dedupe: options.dedupe,
      score: options.score,
      sort_score: options.sortScore,
      max_links: options.maxLinks,
      tag: options.tag || null,
      log: options.log,
    }),
  });
}

export async function checkUrls(
  urls: string[],
  params: { timeout?: number; retries?: number } = {},
): Promise<CheckResult[]> {
  const data = await jsonFetch<{ results: CheckResult[] }>("/api/check", {
    method: "POST",
    body: JSON.stringify({
      urls,
      timeout: params.timeout ?? null,
      retries: params.retries ?? null,
    }),
  });
  return data.results;
}

export function getSettings(): Promise<Settings> {
  return jsonFetch<Settings>("/api/settings");
}

export function saveSettings(
  settings: Partial<Settings> & { tor?: boolean },
): Promise<Settings> {
  return jsonFetch<Settings>("/api/settings", {
    method: "POST",
    body: JSON.stringify(settings),
  });
}

export async function getCustomPlatforms(): Promise<CustomPlatformMap> {
  const data = await jsonFetch<{ platforms: CustomPlatformMap }>(
    "/api/custom-platforms",
  );
  return data.platforms;
}

export async function addCustomPlatform(
  category: string,
  name: string,
  url: string,
): Promise<CustomPlatformMap> {
  const data = await jsonFetch<{ platforms: CustomPlatformMap }>(
    "/api/custom-platforms",
    { method: "POST", body: JSON.stringify({ category, name, url }) },
  );
  return data.platforms;
}

export async function removeCustomPlatform(
  category: string,
  name: string,
): Promise<CustomPlatformMap> {
  const data = await jsonFetch<{ platforms: CustomPlatformMap }>(
    "/api/custom-platforms",
    { method: "DELETE", body: JSON.stringify({ category, name }) },
  );
  return data.platforms;
}

// ---- Domain-intelligence tools ----
export function enrichDomain(
  domain: string,
  refresh = false,
): Promise<EnrichResult> {
  return jsonFetch<EnrichResult>("/api/enrich", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
}

export async function enrichBulk(
  domains: string[],
  refresh = false,
): Promise<BulkEnrichResponse> {
  return jsonFetch<BulkEnrichResponse>("/api/enrich-bulk", {
    method: "POST",
    body: JSON.stringify({ domains, refresh }),
  });
}

export function takedown(
  enrichment: EnrichResult,
  brand: string,
  reporter: string,
): Promise<TakedownEmail> {
  return jsonFetch<TakedownEmail>("/api/takedown", {
    method: "POST",
    body: JSON.stringify({ enrichment, brand, reporter }),
  });
}

export function ipPivot(domain: string, refresh = false): Promise<IpPivotResult> {
  return jsonFetch<IpPivotResult>("/api/ip-pivot", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
}

export function abuseRoute(
  domain: string,
  refresh = false,
): Promise<AbuseRouteResult> {
  return jsonFetch<AbuseRouteResult>("/api/abuse-route", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
}

export async function domainMatch(
  domain: string,
  refresh = false,
): Promise<DomainMatch[]> {
  const d = await jsonFetch<{ matches: DomainMatch[] }>("/api/domain-match", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
  return d.matches;
}

export async function dnstwist(
  domain: string,
  refresh = false,
): Promise<DnstwistEntry[]> {
  const d = await jsonFetch<{ results: DnstwistEntry[] }>("/api/dnstwist", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
  return d.results;
}

export function cloneDetect(
  domain: string,
  refresh = false,
): Promise<CloneDetectResult> {
  return jsonFetch<CloneDetectResult>("/api/clone-detect", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
}

export async function textClone(text: string): Promise<SearchResult[]> {
  const d = await jsonFetch<{ links: SearchResult[] }>("/api/text-clone", {
    method: "POST",
    body: JSON.stringify({ text }),
  });
  return d.links;
}

export async function phishingDorks(keywords: string[]): Promise<SearchResult[]> {
  const d = await jsonFetch<{ links: SearchResult[] }>("/api/phishing-dorks", {
    method: "POST",
    body: JSON.stringify({ keywords }),
  });
  return d.links;
}

export function deepSearch(
  target: string,
  score: boolean,
  refresh = false,
): Promise<DeepSearchResponse> {
  return jsonFetch<DeepSearchResponse>("/api/deep-search", {
    method: "POST",
    body: JSON.stringify({ target, score, refresh }),
  });
}

export function brandAbuse(
  regex: string,
  idOnly: boolean,
  refresh = false,
): Promise<BrandAbuseResponse> {
  return jsonFetch<BrandAbuseResponse>("/api/brand-abuse", {
    method: "POST",
    body: JSON.stringify({ regex, id_only: idOnly, refresh }),
  });
}

export async function screenshot(url: string): Promise<string> {
  const d = await jsonFetch<{ image: string }>("/api/screenshot", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
  return d.image;
}

export function generateRegex(
  value: string,
  level: RegexLevel,
): Promise<GenerateRegexResponse> {
  return jsonFetch<GenerateRegexResponse>("/api/generate-regex", {
    method: "POST",
    body: JSON.stringify({ value, level }),
  });
}

// ---- History + Cases (persistence) ----
export async function getHistory(limit = 100): Promise<HistoryEntry[]> {
  const d = await jsonFetch<{ history: HistoryEntry[] }>(
    `/api/history?limit=${limit}`,
  );
  return d.history;
}

export async function clearHistory(): Promise<void> {
  await jsonFetch("/api/history", { method: "DELETE" });
}

export async function getCases(): Promise<CaseSummary[]> {
  const d = await jsonFetch<{ cases: CaseSummary[] }>("/api/cases");
  return d.cases;
}

export function createCase(name: string, note = ""): Promise<CaseDetail> {
  return jsonFetch<CaseDetail>("/api/cases", {
    method: "POST",
    body: JSON.stringify({ name, note }),
  });
}

export function getCase(id: number): Promise<CaseDetail> {
  return jsonFetch<CaseDetail>(`/api/cases/${id}`);
}

export async function deleteCase(id: number): Promise<void> {
  await jsonFetch(`/api/cases/${id}`, { method: "DELETE" });
}

export function addCaseItem(
  caseId: number,
  item: { kind: string; data: unknown; note?: string; status?: string },
): Promise<CaseDetail> {
  return jsonFetch<CaseDetail>(`/api/cases/${caseId}/items`, {
    method: "POST",
    body: JSON.stringify(item),
  });
}

export async function updateCaseItem(
  itemId: number,
  patch: { note?: string; status?: string },
): Promise<void> {
  await jsonFetch(`/api/cases/items/${itemId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export async function deleteCaseItem(itemId: number): Promise<void> {
  await jsonFetch(`/api/cases/items/${itemId}`, { method: "DELETE" });
}

// ---- Monitoring (watchlist + diff) ----
export async function getWatchlist(): Promise<WatchTarget[]> {
  const d = await jsonFetch<{ watchlist: WatchTarget[] }>("/api/watchlist");
  return d.watchlist;
}

export async function addWatch(target: string): Promise<WatchTarget[]> {
  const d = await jsonFetch<{ watchlist: WatchTarget[] }>("/api/watchlist", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
  return d.watchlist;
}

export async function removeWatch(target: string): Promise<WatchTarget[]> {
  const d = await jsonFetch<{ watchlist: WatchTarget[] }>("/api/watchlist", {
    method: "DELETE",
    body: JSON.stringify({ target }),
  });
  return d.watchlist;
}

export function runMonitor(target: string): Promise<MonitorReport> {
  return jsonFetch<MonitorReport>("/api/monitor/run", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export function assessVip(input: VipInput): Promise<VipScorecard> {
  return jsonFetch<VipScorecard>("/api/vip/assess", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

// --- IOC extraction + interop export ---
export function extractIocs(text: string): Promise<IocExtractResult> {
  return jsonFetch<IocExtractResult>("/api/ioc/extract", {
    method: "POST",
    body: JSON.stringify({ text }),
  });
}

export function exportIocs(
  body: { iocs?: IocSet; text?: string; format: "stix" | "misp"; info?: string },
): Promise<unknown> {
  return jsonFetch<unknown>("/api/ioc/export", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function checkReputation(domain: string, refresh = false): Promise<ReputationResult> {
  return jsonFetch<ReputationResult>("/api/reputation", {
    method: "POST",
    body: JSON.stringify({ domain, refresh }),
  });
}

export function analyzeUrl(url: string, refresh = false): Promise<UrlAnalysis> {
  return jsonFetch<UrlAnalysis>("/api/url-analyze", {
    method: "POST",
    body: JSON.stringify({ url, refresh }),
  });
}

export function analyzeEmail(raw: string): Promise<EmailAnalysis> {
  return jsonFetch<EmailAnalysis>("/api/email/analyze", {
    method: "POST",
    body: JSON.stringify({ raw }),
  });
}

export function getMetrics(): Promise<Metrics> {
  return jsonFetch<Metrics>("/api/metrics");
}

// --- Takedown lifecycle tracking ---
export async function getTakedowns(status?: string): Promise<Takedown[]> {
  const q = status ? `?status=${encodeURIComponent(status)}` : "";
  const d = await jsonFetch<{ takedowns: Takedown[] }>(`/api/takedowns${q}`);
  return d.takedowns;
}

export function getTakedown(id: number): Promise<Takedown> {
  return jsonFetch<Takedown>(`/api/takedowns/${id}`);
}

export function createTakedown(input: {
  domain: string;
  case_id?: number | null;
  contact?: string;
  note?: string;
}): Promise<Takedown> {
  return jsonFetch<Takedown>("/api/takedowns", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateTakedown(
  id: number,
  patch: { status?: string; note?: string; contact?: string },
): Promise<Takedown> {
  return jsonFetch<Takedown>(`/api/takedowns/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function checkTakedown(id: number): Promise<Takedown> {
  return jsonFetch<Takedown>(`/api/takedowns/${id}/check`, { method: "POST" });
}

export function checkAllTakedowns(): Promise<{
  checked: number;
  changed: { domain: string; status: string }[];
}> {
  return jsonFetch("/api/takedowns/check-all", { method: "POST" });
}

export function deleteTakedown(id: number): Promise<{ ok: boolean }> {
  return jsonFetch(`/api/takedowns/${id}`, { method: "DELETE" });
}

export async function getAlertChannels(): Promise<AlertChannels> {
  const d = await jsonFetch<{ channels: AlertChannels }>("/api/notify/status");
  return d.channels;
}

export function testAlerts(): Promise<AlertTestResult> {
  return jsonFetch<AlertTestResult>("/api/notify/test", { method: "POST" });
}
