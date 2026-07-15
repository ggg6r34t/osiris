import type {
  BrandAbuseResponse,
  GenerateRegexResponse,
  RegexLevel,
  CheckResult,
  CloneDetectResult,
  CustomPlatformMap,
  DeepSearchResponse,
  DnstwistEntry,
  DomainMatch,
  EnrichResult,
  PlatformsResponse,
  SearchOptions,
  SearchResponse,
  SearchResult,
  Settings,
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

// ---- Domain-intelligence tools (Phase 2) ----
export function enrichDomain(domain: string): Promise<EnrichResult> {
  return jsonFetch<EnrichResult>("/api/enrich", {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
}

export async function domainMatch(domain: string): Promise<DomainMatch[]> {
  const d = await jsonFetch<{ matches: DomainMatch[] }>("/api/domain-match", {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
  return d.matches;
}

export async function dnstwist(domain: string): Promise<DnstwistEntry[]> {
  const d = await jsonFetch<{ results: DnstwistEntry[] }>("/api/dnstwist", {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
  return d.results;
}

export function cloneDetect(domain: string): Promise<CloneDetectResult> {
  return jsonFetch<CloneDetectResult>("/api/clone-detect", {
    method: "POST",
    body: JSON.stringify({ domain }),
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
): Promise<DeepSearchResponse> {
  return jsonFetch<DeepSearchResponse>("/api/deep-search", {
    method: "POST",
    body: JSON.stringify({ target, score }),
  });
}

export function brandAbuse(
  regex: string,
  idOnly: boolean,
): Promise<BrandAbuseResponse> {
  return jsonFetch<BrandAbuseResponse>("/api/brand-abuse", {
    method: "POST",
    body: JSON.stringify({ regex, id_only: idOnly }),
  });
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
