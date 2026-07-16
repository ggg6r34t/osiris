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
"""


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
