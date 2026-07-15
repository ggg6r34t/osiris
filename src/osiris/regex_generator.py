"""Generate typosquat/homoglyph-tolerant regexes from a brand or domain.

Used by the Brand Abuse (regex) tool so an analyst can turn a brand name into a
pattern for the Panda regex search instead of hand-crafting it. Pure/offline.

Levels:
  conservative — homoglyph swaps only (tightest, least noise)
  balanced     — homoglyph swaps + optional letter doubling + optional separator
                 (same style as the hand-written reference patterns)
  aggressive   — repetition on every char + separators between every char + a
                 wider homoglyph/leet set (widest recall, most false positives)
"""
import re
from urllib.parse import urlparse

# Classic visual confusables (used by conservative + balanced).
_HOMOGLYPHS_BASIC = {
    "a": ["a", "4"],
    "e": ["e", "3"],
    "i": ["i", "l"],
    "l": ["l", "i"],
    "o": ["o", "0"],
    "s": ["s", "5"],
}

# Wider leetspeak set (used by aggressive).
_HOMOGLYPHS_WIDE = {
    "a": ["a", "4", "@"],
    "b": ["b", "8"],
    "e": ["e", "3"],
    "g": ["g", "9"],
    "i": ["i", "l", "1", "!"],
    "l": ["l", "i", "1"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
    "u": ["u", "v"],
    "z": ["z", "2"],
}

LEVELS = ("conservative", "balanced", "aggressive")


def brand_label(value: str) -> str:
    """Reduce a brand-or-domain input to the brand label(s).

    - Strips scheme/path.
    - For a domain (no spaces, has a dot): uses the leftmost label (dropping a
      leading 'www'), so 'brand.com', 'brand.co.uk' and 'www.brand.com' all →
      'brand'. Subdomained inputs use the leftmost label; type the brand itself
      for best results.
    - For brand words ('riu hotel', 'riu-hotel'): kept as-is (separators become
      optional in the pattern).
    """
    v = value.strip().lower()
    if "://" in v:
        v = urlparse(v).netloc or v
    elif "/" in v:
        v = v.split("/", 1)[0]

    if " " not in v and "." in v:
        parts = [p for p in v.split(".") if p and p != "www"]
        if parts:
            v = parts[0]
    return v


def _char_pattern(char: str, level: str, homoglyphs: dict) -> str:
    alts = homoglyphs.get(char)
    if level == "conservative":
        return f"({'|'.join(alts)})" if alts else re.escape(char)
    if level == "aggressive":
        if alts:
            cls = "".join(dict.fromkeys(alts))  # order-preserving dedupe
            return f"[{cls}]+"
        return f"{re.escape(char)}+"
    # balanced
    if alts:
        return f"({'|'.join(alts)}){{1,}}"
    esc = re.escape(char)
    return f"{esc}{esc}?"


def generate_brand_regex(value: str, level: str = "balanced") -> str:
    if level not in LEVELS:
        level = "balanced"
    label = brand_label(value)
    words = [w for w in re.split(r"[\s._-]+", label) if w]
    if not words:
        return ""

    homoglyphs = _HOMOGLYPHS_WIDE if level == "aggressive" else _HOMOGLYPHS_BASIC

    def build_word(word: str) -> str:
        patterns = [_char_pattern(c, level, homoglyphs) for c in word]
        return ("[-.]?".join(patterns)) if level == "aggressive" else "".join(patterns)

    if level == "aggressive":
        separator = "[-.]?"
    elif level == "conservative":
        separator = r"(\.|-)?"
    else:  # balanced
        separator = r"(\.|-?)?"

    body = separator.join(build_word(w) for w in words)
    return f".*{body}.*"
