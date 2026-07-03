export type OpenOptions = {
  delay: number; // seconds between tabs
  maxOpen: number; // 0 = no limit
  randomize: boolean;
};

/**
 * Open a set of URLs in new browser tabs, staggered by `delay` seconds and
 * capped by `maxOpen`. Mirrors the CLI's --open / --open-delay / --max-open /
 * --randomize behavior, but runs in the user's own browser via window.open.
 *
 * Returns the number of tabs that were opened. Browsers may block bulk pop-ups
 * until the user allows them for this origin.
 */
export function openLinks(urls: string[], options: OpenOptions): number {
  // Only open http(s) URLs — never javascript:/data:/etc.
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

  list.forEach((url, i) => {
    if (i === 0 || options.delay <= 0) {
      window.open(url, "_blank", "noopener,noreferrer");
    } else {
      setTimeout(
        () => window.open(url, "_blank", "noopener,noreferrer"),
        i * options.delay * 1000,
      );
    }
  });

  return list.length;
}
