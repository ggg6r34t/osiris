"""Local SQLite persistence for history, cases and monitoring.

Single-file DB (osiris.db at repo root, gitignored) via stdlib sqlite3 — no
dependency. A single shared connection guarded by a lock is used because FastAPI
handlers run in a threadpool.
"""
import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.getenv("OSIRIS_DB", os.path.join(_ROOT, "osiris.db"))

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool TEXT NOT NULL,
  input TEXT,
  summary TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  note TEXT DEFAULT '',
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS case_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL,
  kind TEXT,
  data TEXT,
  note TEXT DEFAULT '',
  status TEXT DEFAULT 'open',
  ts REAL NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS watchlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL UNIQUE,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS monitor_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  tool TEXT NOT NULL,
  items TEXT,
  ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS takedowns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  case_id INTEGER,
  status TEXT NOT NULL DEFAULT 'new',
  contact TEXT DEFAULT '',
  note TEXT DEFAULT '',
  reported_at REAL,
  last_checked REAL,
  last_state TEXT,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS takedown_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  takedown_id INTEGER NOT NULL,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT DEFAULT '',
  FOREIGN KEY(takedown_id) REFERENCES takedowns(id) ON DELETE CASCADE
);
"""

# Lifecycle states and the liveness states that count as "down" vs "up".
TAKEDOWN_STATES = (
    "new", "reported", "acknowledged", "monitoring",
    "down", "relisted", "closed", "false_positive",
)
_DOWN_STATES = {"suspended", "nxdomain", "no-dns-records", "no-a-record"}
_UP_STATES = {"live", "resolves-no-response"}
# Statuses that are actively awaiting/monitoring a takedown (eligible for checks).
_OPEN_STATES = {"new", "reported", "acknowledged", "monitoring", "down", "relisted"}


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA foreign_keys = ON")
        _conn.executescript(_SCHEMA)
        _conn.commit()
    return _conn


# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
def add_history(tool: str, input_value: str, summary: dict) -> int:
    with _lock:
        db = _db()
        cur = db.execute(
            "INSERT INTO history (tool, input, summary, ts) VALUES (?,?,?,?)",
            (tool, input_value, json.dumps(summary), time.time()),
        )
        db.commit()
        return cur.lastrowid


def list_history(limit: int = 100) -> list[dict]:
    with _lock:
        rows = _db().execute(
            "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "tool": r["tool"],
            "input": r["input"],
            "summary": json.loads(r["summary"] or "{}"),
            "ts": r["ts"],
        }
        for r in rows
    ]


def clear_history() -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM history")
        db.commit()


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
def create_case(name: str, note: str = "") -> int:
    with _lock:
        db = _db()
        cur = db.execute(
            "INSERT INTO cases (name, note, ts) VALUES (?,?,?)",
            (name, note, time.time()),
        )
        db.commit()
        return cur.lastrowid


def list_cases() -> list[dict]:
    with _lock:
        rows = _db().execute(
            """SELECT c.*, COUNT(i.id) AS item_count
               FROM cases c LEFT JOIN case_items i ON i.case_id = c.id
               GROUP BY c.id ORDER BY c.id DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def get_case(case_id: int) -> Optional[dict]:
    with _lock:
        db = _db()
        case = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not case:
            return None
        items = db.execute(
            "SELECT * FROM case_items WHERE case_id=? ORDER BY id DESC", (case_id,)
        ).fetchall()
    return {
        **dict(case),
        "items": [
            {**dict(i), "data": json.loads(i["data"] or "{}")} for i in items
        ],
    }


def add_case_item(
    case_id: int, kind: str, data: Any, note: str = "", status: str = "open"
) -> int:
    with _lock:
        db = _db()
        cur = db.execute(
            "INSERT INTO case_items (case_id, kind, data, note, status, ts) VALUES (?,?,?,?,?,?)",
            (case_id, kind, json.dumps(data), note, status, time.time()),
        )
        db.commit()
        return cur.lastrowid


def update_case_item(item_id: int, note: Optional[str], status: Optional[str]) -> None:
    with _lock:
        db = _db()
        if note is not None:
            db.execute("UPDATE case_items SET note=? WHERE id=?", (note, item_id))
        if status is not None:
            db.execute("UPDATE case_items SET status=? WHERE id=?", (status, item_id))
        db.commit()


def delete_case(case_id: int) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM cases WHERE id=?", (case_id,))
        db.commit()


def delete_case_item(item_id: int) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM case_items WHERE id=?", (item_id,))
        db.commit()


# --------------------------------------------------------------------------- #
# Watchlist + monitoring snapshots (Phase D)
# --------------------------------------------------------------------------- #
def add_watch(target: str) -> None:
    with _lock:
        db = _db()
        db.execute(
            "INSERT OR IGNORE INTO watchlist (target, ts) VALUES (?,?)",
            (target, time.time()),
        )
        db.commit()


def list_watch() -> list[dict]:
    with _lock:
        rows = _db().execute("SELECT * FROM watchlist ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def remove_watch(target: str) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM watchlist WHERE target=?", (target,))
        db.commit()


def latest_snapshot(target: str, tool: str) -> Optional[list]:
    with _lock:
        row = _db().execute(
            "SELECT items FROM monitor_snapshots WHERE target=? AND tool=? ORDER BY id DESC LIMIT 1",
            (target, tool),
        ).fetchone()
    return json.loads(row["items"]) if row else None


def save_snapshot(target: str, tool: str, items: list) -> None:
    with _lock:
        db = _db()
        db.execute(
            "INSERT INTO monitor_snapshots (target, tool, items, ts) VALUES (?,?,?,?)",
            (target, tool, json.dumps(items), time.time()),
        )
        db.commit()


# --------------------------------------------------------------------------- #
# Takedown lifecycle tracking
# --------------------------------------------------------------------------- #
def _add_event(db: sqlite3.Connection, takedown_id: int, kind: str, detail: str = "") -> None:
    db.execute(
        "INSERT INTO takedown_events (takedown_id, ts, kind, detail) VALUES (?,?,?,?)",
        (takedown_id, time.time(), kind, detail),
    )


def create_takedown(
    domain: str, case_id: Optional[int] = None, contact: str = "", note: str = ""
) -> int:
    now = time.time()
    with _lock:
        db = _db()
        cur = db.execute(
            """INSERT INTO takedowns (domain, case_id, status, contact, note, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (domain, case_id, "new", contact, note, now, now),
        )
        tid = cur.lastrowid
        _add_event(db, tid, "created", f"Tracking takedown for {domain}")
        db.commit()
        return tid


def list_takedowns(status: Optional[str] = None) -> list[dict]:
    with _lock:
        db = _db()
        if status:
            rows = db.execute(
                "SELECT * FROM takedowns WHERE status=? ORDER BY updated_at DESC", (status,)
            ).fetchall()
        else:
            rows = db.execute("SELECT * FROM takedowns ORDER BY updated_at DESC").fetchall()
    return [dict(r) for r in rows]


def get_takedown(takedown_id: int) -> Optional[dict]:
    with _lock:
        db = _db()
        row = db.execute("SELECT * FROM takedowns WHERE id=?", (takedown_id,)).fetchone()
        if not row:
            return None
        events = db.execute(
            "SELECT * FROM takedown_events WHERE takedown_id=? ORDER BY id DESC", (takedown_id,)
        ).fetchall()
    return {**dict(row), "events": [dict(e) for e in events]}


def update_takedown(
    takedown_id: int,
    status: Optional[str] = None,
    note: Optional[str] = None,
    contact: Optional[str] = None,
) -> Optional[dict]:
    now = time.time()
    with _lock:
        db = _db()
        row = db.execute("SELECT * FROM takedowns WHERE id=?", (takedown_id,)).fetchone()
        if not row:
            return None
        if status is not None and status != row["status"]:
            db.execute("UPDATE takedowns SET status=? WHERE id=?", (status, takedown_id))
            if status == "reported" and not row["reported_at"]:
                db.execute(
                    "UPDATE takedowns SET reported_at=? WHERE id=?", (now, takedown_id)
                )
            _add_event(db, takedown_id, "status", status)
        if contact is not None:
            db.execute("UPDATE takedowns SET contact=? WHERE id=?", (contact, takedown_id))
        if note:
            db.execute("UPDATE takedowns SET note=? WHERE id=?", (note, takedown_id))
            _add_event(db, takedown_id, "note", note)
        db.execute("UPDATE takedowns SET updated_at=? WHERE id=?", (now, takedown_id))
        db.commit()
    return get_takedown(takedown_id)


def record_takedown_check(takedown_id: int, state: str) -> Optional[dict]:
    """Record a liveness check and auto-transition: mark 'down' when a reported
    domain goes dark, or 'relisted' when a down domain comes back up."""
    now = time.time()
    with _lock:
        db = _db()
        row = db.execute("SELECT * FROM takedowns WHERE id=?", (takedown_id,)).fetchone()
        if not row:
            return None
        cur_status = row["status"]
        new_status = cur_status
        if cur_status in {"reported", "acknowledged", "monitoring"} and state in _DOWN_STATES:
            new_status = "down"
            _add_event(db, takedown_id, "auto", f"Detected DOWN ({state})")
        elif cur_status == "down" and state in _UP_STATES:
            new_status = "relisted"
            _add_event(db, takedown_id, "auto", f"RELISTED — back up ({state})")
        db.execute(
            "UPDATE takedowns SET last_checked=?, last_state=?, status=?, updated_at=? WHERE id=?",
            (now, state, new_status, now, takedown_id),
        )
        db.commit()
    result = get_takedown(takedown_id)
    if result:
        result["status_changed"] = new_status != cur_status
    return result


def open_takedowns() -> list[dict]:
    """Takedowns still worth re-checking (not closed / false-positive)."""
    return [t for t in list_takedowns() if t["status"] in _OPEN_STATES]


def delete_takedown(takedown_id: int) -> None:
    with _lock:
        db = _db()
        db.execute("DELETE FROM takedowns WHERE id=?", (takedown_id,))
        db.commit()
