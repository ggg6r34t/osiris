"""Monitoring: re-run lookalike tools for a target and diff vs the last snapshot.

Manual-run model (no daemon) — call run_monitor() from the API ("Run monitor")
or the CLI (`osiris --monitor`, cron-friendly). Snapshots are stored in SQLite;
each run reports NEW / gone domains relative to the previous run.
"""
from typing import Callable

from osiris import storage
from osiris.domain_matcher import find_similar_domains
from osiris.dnstwist import run_dnstwist


def _match_domains(target: str) -> list[str]:
    matches = find_similar_domains(target, max_whois=0)
    return sorted(
        {m["domain"] for m in matches if isinstance(m, dict) and m.get("domain")}
    )


def _dnstwist_domains(target: str) -> list[str]:
    results = run_dnstwist(target) or []
    return sorted(
        {e["domain"] for e in results if isinstance(e, dict) and e.get("dns_a")}
    )


def diff(prev: list[str] | None, current: list[str]) -> dict:
    """Pure diff of two domain lists → new / gone (empty on first run)."""
    if prev is None:
        return {"new": [], "gone": [], "first_run": True}
    prev_set, cur_set = set(prev), set(current)
    return {
        "new": sorted(cur_set - prev_set),
        "gone": sorted(prev_set - cur_set),
        "first_run": False,
    }


def run_monitor(target: str) -> dict:
    """Run each monitor tool for `target`, diff vs last snapshot, persist, and
    return {tool: {current, new, gone, first_run}}."""
    tools: dict[str, Callable[[str], list[str]]] = {
        "domain-match": _match_domains,
        "dnstwist": _dnstwist_domains,
    }
    report: dict = {}
    for tool, fn in tools.items():
        try:
            current = fn(target)
        except Exception:  # noqa: BLE001 - one tool failing shouldn't abort the run
            current = []
        prev = storage.latest_snapshot(target, tool)
        d = diff(prev, current)
        storage.save_snapshot(target, tool, current)
        report[tool] = {"current": current, **d}

    storage.add_watch(target)
    return report
