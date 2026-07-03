/**
 * Returns true only for http(s) URLs. Used to neutralize dangerous schemes
 * (javascript:, data:, etc.) before rendering a URL as a live link or opening it.
 */
export function isHttpUrl(url: string): boolean {
  const u = url.trim().toLowerCase();
  return u.startsWith("http://") || u.startsWith("https://");
}

/** Safe href for anchors: the URL if it is http(s), otherwise "#". */
export function safeHref(url: string): string {
  return isHttpUrl(url) ? url : "#";
}
