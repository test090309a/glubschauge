"""Event-Datenklasse und SQLite-Persistenz."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Event:
    """Ein erkanntes Ereignis – Input für LLM-Bewertung und TUI."""
    detector: str
    timestamp: datetime
    severity_hint: int          # 0–10, Regel-Schätzung (LLM darf später überschreiben)
    title: str
    src: str = ""
    dst: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> tuple:
        return (
            self.timestamp.isoformat(),
            self.detector,
            self.severity_hint,
            self.title,
            self.src,
            self.dst,
            json.dumps(self.details, default=str, ensure_ascii=False),
        )


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    detector      TEXT    NOT NULL,
    severity_hint INTEGER NOT NULL,
    title         TEXT    NOT NULL,
    src           TEXT    NOT NULL DEFAULT '',
    dst           TEXT    NOT NULL DEFAULT '',
    details_json  TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_detector ON events(detector);

CREATE TABLE IF NOT EXISTS hosts (
    mac        TEXT NOT NULL,
    ip         TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);

CREATE TABLE IF NOT EXISTS event_evaluations (
    event_id    INTEGER PRIMARY KEY,
    model       TEXT    NOT NULL,
    severity    INTEGER NOT NULL,
    category    TEXT    NOT NULL,
    explanation TEXT    NOT NULL,
    raw_json    TEXT    NOT NULL DEFAULT '{}',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    ts          TEXT    NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);
"""


class EventStore:
    """Dünne SQLite-Hülle. Synchron – Aufrufe aus einem Thread."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def write(self, ev: Event) -> int:
        cur = self._conn.execute(
            "INSERT INTO events (ts, detector, severity_hint, title, src, dst, details_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            ev.to_row(),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def count(self) -> int:
        cur = self._conn.execute("SELECT COUNT(*) FROM events")
        return int(cur.fetchone()[0])

    def recent(self, limit: int = 20) -> list[tuple]:
        cur = self._conn.execute(
            "SELECT id, ts, detector, severity_hint, title"
            " FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()

    def close(self) -> None:
        self._conn.close()

    def load_hosts(self) -> set[tuple[str, str]]:
        cur = self._conn.execute("SELECT mac, ip FROM hosts")
        return {(mac, ip) for mac, ip in cur.fetchall()}

    def remember_host(self, mac: str, ip: str, ts: datetime) -> None:
        iso = ts.isoformat()
        self._conn.execute(
            "INSERT INTO hosts (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
            (mac, ip, iso, iso),
        )
        self._conn.commit()

    def write_evaluation(
        self,
        event_id: int,
        model: str,
        severity: int,
        category: str,
        explanation: str,
        raw: str = "{}",
        duration_ms: int = 0,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO event_evaluations"
            " (event_id, model, severity, category, explanation, raw_json, duration_ms, ts)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, model, severity, category, explanation, raw,
             duration_ms, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def get_event_full(self, event_id: int) -> dict | None:
        """Alle Daten eines Events inkl. LLM-Bewertung."""
        row = self._conn.execute(
            """
            SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
                   e.src, e.dst, e.details_json,
                   v.severity, v.category, v.explanation, v.model, v.duration_ms
            FROM events e
            LEFT JOIN event_evaluations v ON v.event_id = e.id
            WHERE e.id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "ts": row[1], "detector": row[2],
            "severity_hint": row[3], "title": row[4],
            "src": row[5], "dst": row[6], "details": row[7],
            "llm_severity": row[8], "llm_category": row[9],
            "llm_explanation": row[10], "llm_model": row[11],
            "llm_duration_ms": row[12],
        }