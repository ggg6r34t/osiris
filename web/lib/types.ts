export type SearchResult = {
  platform: string;
  category: string;
  url: string;
  target?: string;
  tag?: string;
  score?: number;
  label?: string;
  reasons?: string[];
};

export type PlatformsResponse = {
  categories: string[];
  platforms: Record<string, string[]>;
};

export type SearchResponse = {
  targets: string[];
  count: number;
  results: SearchResult[];
};

export type SearchOptions = {
  fuzzy: boolean;
  dedupe: boolean;
  score: boolean;
  sortScore: boolean;
  maxLinks: number;
  excludePlatforms: string[];
  excludeCategories: string[];
  tag: string;
  log: boolean;
};

export type CheckResult = {
  url: string;
  ok: boolean;
  status: number | null;
};

export type Settings = {
  user_agent: string;
  verify_tls: boolean;
  request_timeout: number;
  rate_limit: number;
  http_proxy: string;
  https_proxy: string;
};

export type CustomPlatformMap = Record<string, Record<string, string>>;

// ---- Domain-intelligence tools (Phase 2) ----
export type WhoisInfo = {
  domain_info?: { registrar?: string; tld?: string; status?: unknown };
  registration_dates?: {
    creation_date?: string | null;
    expiration_date?: string | null;
    domain_age_days?: number | null;
    recently_created?: boolean;
  };
  contacts?: { emails?: string[] };
  name_servers?: string[];
  scam_indicators?: Record<string, boolean>;
  error?: string;
};

export type DomainMatch = {
  domain: string;
  matched_variant: string;
  whois?: WhoisInfo;
};

export type EnrichResult = {
  target: string;
  domain: string;
  risk_score: number;
  whois?: WhoisInfo;
  dns?: Record<string, string[] | string>;
  host?: {
    ip?: string;
    asn?: string;
    hosted_by?: string;
    geolocation?: { country?: string; isp?: string };
    abuse_contact?: { email?: string };
    host_error?: string;
  };
  ssl_certificate?: {
    issuer?: Record<string, string>;
    valid_to?: string;
    is_self_signed?: boolean;
    low_trust_ca?: boolean;
    error?: string;
  };
  lookalike_domains?: DomainMatch[];
  favicon?: { favicon_url?: string; favicon_hash_md5?: string; error?: string };
  page_metadata?: { title?: string; phishing_keywords_found?: boolean };
  content_hash?: string | null;
};

export type DnstwistEntry = {
  domain: string;
  fuzzer?: string;
  dns_a: string[];
  dns_ns?: string[];
  dns_mx?: string[];
  whois_created?: string | null;
  whois_updated?: string | null;
  whois_expires?: string | null;
};

export type CloneDetectResult = {
  domain: string;
  variants_checked: number;
  clones: string[];
};

export type BrandAbuseMatch = {
  id: string;
  domain: string | null;
  url: string | null;
  raw: Record<string, unknown> | null;
};

export type BrandAbuseResponse = {
  regex: string;
  count: number;
  results: BrandAbuseMatch[];
};

export type RegexLevel = "conservative" | "balanced" | "aggressive";

export type GenerateRegexResponse = {
  regex: string;
  level: RegexLevel;
  brand: string;
  short: boolean;
};

export type DeepSearchResponse = {
  target: string;
  count: number;
  links: SearchResult[];
  results: {
    enrichment?: EnrichResult;
    typo_domains?: DomainMatch[];
    clone_sites?: string[];
    text_clones?: SearchResult[];
    phishing_dorks?: SearchResult[];
  };
};
