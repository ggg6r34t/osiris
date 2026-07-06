export type OpenOptions = {
  maxOpen: number; // 0 = no limit
  randomize: boolean;
};

/**
 * Open a set of URLs in new browser tabs, capped by `maxOpen` and optionally
 * shuffled. All tabs are opened synchronously inside the caller's click handler:
 * browsers only permit window.open within a direct user gesture, so staggering
 * with setTimeout would get every tab after the first killed by the pop-up
 * blocker. The browser may still prompt to allow pop-ups the first time; once
 * allowed, all tabs open.
 *
 * Only http(s) URLs are opened (never javascript:/data:/etc.).
 * Returns { opened, attempted } so the caller can warn if the blocker ate some.
 */
export function openLinks(
  urls: string[],
  options: OpenOptions,
): { opened: number; attempted: number } {
  let list = urls.filter((u) => {
    const s = u.trim().toLowerCase();
    return s.startsWith("http://") || s.startsWith("https://");
  });

  if (options.randomize) {
    for (let i = list.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [list[i], list[j]] = [list[j], list[i]];
    }
  }
  if (options.maxOpen > 0) {
    list = list.slice(0, options.maxOpen);
  }

  let opened = 0;
  for (const url of list) {
    const win = window.open(url, "_blank", "noopener,noreferrer");
    if (win) opened += 1;
  }

  return { opened, attempted: list.length };
}
