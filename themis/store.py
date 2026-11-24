"""SQLite state: events, the journal cursor, and what has been seen before (USB devices, services)."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from .rules import SEVERITIES, Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    message  TEXT NOT NULL,
    source   TEXT NOT NULL DEFAULT '',
    data     TEXT NOT NULL DEFAULT '{}',
    alerted  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source, ts);
CREATE TABLE IF NOT EXISTS known (
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS state (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ignore (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind  TEXT NOT NULL,
    match TEXT NOT NULL DEFAULT '',
    added REAL NOT NULL
);
"""


def default_path() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return base / "themis" / "themis.db"


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not os.path.exists(self.path):  # the log names users and addresses: owner-only
                os.close(os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600))
        self._mem = sqlite3.connect(":memory:") if self.path == ":memory:" else None
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        if self._mem is not None:
            return self._mem
        c = sqlite3.connect(self.path, timeout=10)
        return c

    def _run(self, fn):
        if self._mem is not None:
            with self._mem:
                return fn(self._mem)
        with closing(self._conn()) as c, c:
            c.row_factory = sqlite3.Row
            return fn(c)

    # --- key/value
    def get(self, key: str, default: str = "") -> str:
        row = self._run(lambda c: c.execute("SELECT v FROM state WHERE k = ?", (key,)).fetchone())
        return row[0] if row else default

    def put(self, key: str, value: str) -> None:
        self._run(lambda c: c.execute("INSERT INTO state (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = "
                                      "excluded.v", (key, value)))

    # --- seen before
    def is_known(self, kind: str, key: str) -> bool:
        return self._run(lambda c: c.execute("SELECT 1 FROM known WHERE kind = ? AND key = ?",
                                             (kind, key)).fetchone()) is not None

    def remember(self, kind: str, key: str, label: str = "", ts: float | None = None) -> None:
        self._run(lambda c: c.execute("INSERT OR IGNORE INTO known (kind, key, label, first_seen) VALUES (?, ?, ?, ?)",
                                      (kind, key, label, ts or time.time())))

    def known(self, kind: str) -> list[dict]:
        rows = self._run(lambda c: c.execute("SELECT key, label, first_seen FROM known WHERE kind = ? ORDER BY "
                                             "first_seen, key", (kind,)).fetchall())
        return [{"key": r[0], "label": r[1], "first_seen": r[2]} for r in rows]

    # --- ignore rules: matching events are kept as "info" and never pushed
    def add_ignore(self, kind: str, match: str = "") -> int:
        return self._run(lambda c: c.execute("INSERT INTO ignore (kind, match, added) VALUES (?, ?, ?)",
                                             (kind, match, time.time())).lastrowid)

    def ignores(self) -> list[dict]:
        rows = self._run(lambda c: c.execute("SELECT id, kind, match, added FROM ignore ORDER BY id").fetchall())
        return [{"id": r[0], "kind": r[1], "match": r[2], "added": r[3]} for r in rows]

    def remove_ignore(self, rule_id: int) -> bool:
        return self._run(lambda c: c.execute("DELETE FROM ignore WHERE id = ?", (rule_id,)).rowcount) > 0

    # --- events
    def add(self, f: Finding, alerted: bool = False) -> int:
        return self._run(lambda c: c.execute(
            "INSERT INTO events (ts, kind, severity, message, source, data, alerted) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f.ts, f.kind, f.severity, f.message, f.source, json.dumps(f.data, sort_keys=True), int(alerted))
        ).lastrowid)

    def count(self, kinds: tuple[str, ...], source: str, since: float, until: float) -> int:
        marks = ",".join("?" * len(kinds))
        sql = f"SELECT COUNT(*) FROM events WHERE kind IN ({marks}) AND source = ? AND ts >= ? AND ts <= ?"  # nosec B608
        return self._run(lambda c: c.execute(sql, (*kinds, source, since, until)).fetchone()[0])

    def events(self, since: float = 0.0, min_severity: str = "info", limit: int = 1000) -> list[dict]:
        allowed = SEVERITIES[SEVERITIES.index(min_severity):]
        marks = ",".join("?" * len(allowed))
        sql = (f"SELECT id, ts, kind, severity, message, source, data, alerted FROM events "  # nosec B608
               f"WHERE ts >= ? AND severity IN ({marks}) ORDER BY ts DESC, id DESC LIMIT ?")
        rows = self._run(lambda c: c.execute(sql, (since, *allowed, limit)).fetchall())
        keys = ("id", "ts", "kind", "severity", "message", "source", "data", "alerted")
        out = []
        for r in rows:
            d = dict(zip(keys, r))
            d["data"] = json.loads(d["data"])
            d["alerted"] = bool(d["alerted"])
            out.append(d)
        return out

    def unalerted(self, min_severity: str) -> list[dict]:
        return [e for e in self.events(min_severity=min_severity, limit=200) if not e["alerted"]][::-1]

    def mark_alerted(self, ids: list[int]) -> None:
        if ids:
            marks = ",".join("?" * len(ids))
            self._run(lambda c: c.execute(f"UPDATE events SET alerted = 1 WHERE id IN ({marks})", ids))  # nosec B608
