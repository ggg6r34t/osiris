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
  threat_intel?: {
    abuseipdb?: { abuseConfidenceScore?: number } & Record<string, unknown>;
    virustotal?: {
      malicious?: number;
      suspicious?: number;
      harmless?: number;
      undetected?: number;
      reputation?: number;
      error?: string;
    };
    urlscan?: { scans?: number; recent?: string[] };
  };
};

export type IpPivotResult = {
  target: string;
  ip: string | null;
  asn?: string | null;
  network?: string | null;
  country?: string | null;
  domain_count?: number;
  domains?: string[];
  error?: string;
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

export type HistoryEntry = {
  id: number;
  tool: string;
  input: string;
  summary: Record<string, unknown>;
  ts: number;
};

export type CaseSummary = {
  id: number;
  name: string;
  note: string;
  ts: number;
  item_count: number;
};

export type CaseItem = {
  id: number;
  case_id: number;
  kind: string;
  data: Record<string, unknown>;
  note: string;
  status: string;
  ts: number;
};

export type CaseDetail = {
  id: number;
  name: string;
  note: string;
  ts: number;
  items: CaseItem[];
};

export type WatchTarget = { id: number; target: string; ts: number };

export type MonitorToolReport = {
  current: string[];
  new: string[];
  gone: string[];
  first_run: boolean;
};

export type MonitorReport = {
  target: string;
  report: Record<string, MonitorToolReport>;
};

export type RiskLevel = "high" | "medium" | "low" | "unknown";

export type IocSet = {
  domains: string[];
  ips: string[];
  urls: string[];
  emails: string[];
  hashes: { md5: string[]; sha1: string[]; sha256: string[] };
  cves: string[];
};

export type IocExtractResult = { iocs: IocSet; count: number };

export type EmailAnalysis = {
  headers: {
    from: string;
    from_name: string;
    from_domain: string;
    to: string;
    subject: string;
    date: string;
    reply_to: string;
    return_path: string;
    message_id: string;
    x_mailer: string;
  };
  auth: { spf: string | null; dkim: string | null; dmarc: string | null };
  origin_ip: string | null;
  received_chain: { raw: string; ips: string[] }[];
  flags: { level: "high" | "medium" | "low"; text: string }[];
  risk: "high" | "medium" | "low";
  iocs: IocSet;
  attachments: {
    filename: string;
    content_type: string;
    size: number;
    md5: string | null;
    sha256: string | null;
  }[];
};

export type UrlAnalysis = {
  input: string;
  reachable: boolean;
  error?: string;
  final_url?: string;
  status_code?: number;
  final_domain?: string;
  title?: string;
  redirect_chain?: { url: string; status: number; server: string }[];
  forms?: {
    action: string;
    method: string;
    has_password: boolean;
    cross_domain: boolean;
    suspicious_scheme: boolean;
    input_count: number;
  }[];
  credential_forms?: number;
  targeted_brands?: string[];
  meta_refresh?: boolean;
  flags?: { level: "high" | "medium" | "low"; text: string }[];
  risk?: "high" | "medium" | "low";
  iocs?: IocSet;
};

export type ReputationSource = {
  source: string;
  listed: boolean | null;
  detail?: string;
  reference?: string;
};

export type ReputationResult = {
  target: string;
  is_ip: boolean;
  sources: ReputationSource[];
  listed_count: number;
  verdict: "listed" | "clean" | "unknown";
};

export type AbuseContactMethod = "email" | "form" | "none";

export type AbuseEscalation = {
  order: number;
  target: string;
  label: string;
  method: AbuseContactMethod;
  value: string;
  form?: string;
  why: string;
};

export type AbuseRouteResult = {
  domain: string;
  verdict: { state: string; label: string; notes: string[] };
  dns: { A: string[]; AAAA: string[]; NS: string[]; nxdomain: boolean };
  registrar: {
    name: string | null;
    iana_id: string | null;
    registration: string | null;
    expiration: string | null;
    status: string[];
    abuse_email: string | null;
    abuse_form: string | null;
    abuse_phone: string | null;
    rdap_note?: string;
  };
  registrant: { name?: string | null; org?: string | null; email?: string | null; address?: string | null };
  hosting: {
    ip: string | null;
    asn: string | null;
    network: string | null;
    cdn: string | null;
    abuse_email: string | null;
    abuse_form: string | null;
    geolocation?: Record<string, unknown>;
  };
  email: {
    mx: string[];
    mx_hosts: string[];
    has_mx: boolean;
    spf: boolean;
    dmarc: boolean;
    provider: string | null;
    abuse_email: string | null;
    abuse_form: string | null;
    note: string;
  };
  escalation: AbuseEscalation[];
  reporting_channels: { name: string; method: AbuseContactMethod; value: string }[];
  report_email: { to: string; subject: string; body: string };
};

export type VipInput = {
  name: string;
  aliases: string[];
  emails: string[];
  usernames: string[];
  company: string;
  country: string;
  known_impersonations: number;
};

export type VipPivot = { label: string; url: string };
export type VipSearchPivot = { platform: string; category: string; url: string };

export type VipScorecard = {
  profile: VipInput;
  levels: {
    presence: RiskLevel;
    discoverability: RiskLevel;
    geo: RiskLevel;
    impersonation: RiskLevel;
  };
  overall_score: number;
  presence: {
    resolved_count: number;
    profiles: { platform: string; url: string; username: string }[];
    checked_platforms: number;
    footprint_level: RiskLevel;
    mention: {
      configured: boolean;
      level: RiskLevel;
      query?: string;
      web_results?: number;
      news_results?: number;
      has_infobox?: boolean;
      more_results_available?: boolean;
      error?: string;
    };
  };
  discoverability: {
    hibp_configured: boolean;
    breach_count: number;
    emails: {
      email: string;
      configured: boolean;
      count: number;
      breaches: string[];
      error?: string;
    }[];
  };
  impersonation: { confirmed: number };
  geo: { country: string };
  pivots: {
    social: VipSearchPivot[];
    family: VipPivot[];
    business: VipPivot[];
    geo: VipPivot[];
  };
};

export type TakedownStatus =
  | "new"
  | "reported"
  | "acknowledged"
  | "monitoring"
  | "down"
  | "relisted"
  | "closed"
  | "false_positive";

export type TakedownEvent = {
  id: number;
  takedown_id: number;
  ts: number;
  kind: string;
  detail: string;
};

export type Takedown = {
  id: number;
  domain: string;
  case_id: number | null;
  status: TakedownStatus;
  contact: string;
  note: string;
  reported_at: number | null;
  last_checked: number | null;
  last_state: string | null;
  created_at: number;
  updated_at: number;
  age_days: number | null;
  events?: TakedownEvent[];
  status_changed?: boolean;
};

export type PlaybookDef = {
  id: string;
  name: string;
  description: string;
  target_label: string;
};

export type PlaybookStep = {
  key: string;
  label: string;
  status: "ok" | "error" | "skipped";
  summary: string;
  error: string | null;
  data: unknown;
};

export type PlaybookReport = {
  playbook: string;
  name: string;
  target: string;
  steps: PlaybookStep[];
  risk: { level: "high" | "medium" | "low" | "unknown"; reasons: string[] };
  case_id: number | null;
  takedown_id: number | null;
  candidates?: string[];
  recommendations: string[];
};

export type Metrics = {
  takedowns: {
    total: number;
    open: number;
    relisted: number;
    by_status: Record<string, number>;
    aging: { "0-7": number; "8-30": number; "31+": number };
    mttr_days_mean: number | null;
    mttr_days_median: number | null;
    resolved_count: number;
  };
  cases: { total: number; items_by_status: Record<string, number> };
  history: { total: number; by_tool: Record<string, number> };
  watchlist: number;
};

export type AlertChannels = { telegram: boolean; webhook: boolean };

export type AlertTestResult = {
  configured: boolean;
  channels: AlertChannels;
  results: Record<string, { ok?: boolean; skipped?: boolean; status?: number; error?: string }>;
};

export type RegexLevel = "conservative" | "balanced" | "aggressive";

export type GenerateRegexResponse = {
  regex: string;
  level: RegexLevel;
  brand: string;
  short: boolean;
};

export type BulkEnrichRow = {
  domain: string;
  risk_score?: number | null;
  registrar?: string | null;
  ip?: string | null;
  country?: string | null;
  lookalikes?: number;
  error?: string;
};

export type BulkEnrichResponse = {
  count: number;
  results: BulkEnrichRow[];
};

export type TakedownEmail = {
  to: string;
  subject: string;
  body: string;
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
