"""Event-Datenklasse und SQLite-Persistenz."""
from __future__ import annotations

import json
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

@dataclass(slots=True)
class Event:
    """Ein erkanntes Ereignis – Input für LLM-Bewertung und TUI."""
    detector: str
    timestamp: datetime
    severity_hint: int
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

CREATE TABLE IF NOT EXISTS hosts_mac (
    mac        TEXT PRIMARY KEY,
    vendor     TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_evaluations (
    event_id    INTEGER PRIMARY KEY,
    model       TEXT    NOT NULL,
    severity    INTEGER NOT NULL,
    category    TEXT    NOT NULL,
    explanation TEXT    NOT NULL,
    raw_json    TEXT    NOT NULL DEFAULT '{}',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    ts          TEXT    NOT NULL
);
"""


class EventStore:
    """Dünne SQLite-Hülle. Synchron – Aufrufe aus einem Thread."""

    def __init__(self, db_path: str | Path, retention_days: int = 7) -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.executescript(SCHEMA)
        self._cleanup(retention_days)
        self._conn.commit()

    def _cleanup(self, days: int) -> None:
        """Löscht alte Events, um DB-Wachstum zu begrenzen."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        if cur.rowcount > 0:
            log.info("Cleanup: %d alte Events entfernt.", cur.rowcount)
            self._conn.commit()             # ← erst committen
            self._conn.execute("VACUUM")    # ← dann vacuumen

    def write(self, ev: Event) -> int:
        cur = self._conn.execute(
            "INSERT INTO events (ts, detector, severity_hint, title, src, dst, details_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            ev.to_row(),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def load_hosts(self) -> set[tuple[str, str]]:
        return {(r[0], r[1]) for r in self._conn.execute("SELECT mac, ip FROM hosts").fetchall()}

    def load_macs(self) -> set[str]:
        return {r[0] for r in self._conn.execute("SELECT mac FROM hosts_mac").fetchall()}

    def remember_host(self, mac: str, ip: str, ts: datetime) -> None:
        iso = ts.isoformat()
        self._conn.execute(
            "INSERT INTO hosts (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac, ip) DO UPDATE SET last_seen = ?", (mac, ip, iso, iso, iso)
        )
        self._conn.commit()

    def upsert_mac(self, mac: str, vendor: str, ts: datetime) -> None:
        iso = ts.isoformat()
        self._conn.execute(
            "INSERT INTO hosts_mac (mac, vendor, first_seen, last_seen) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac) DO UPDATE SET last_seen = ?", (mac, vendor, iso, iso, iso)
        )
        self._conn.commit()

    def touch_mac(self, mac: str, ts: datetime) -> None:
            iso = ts.isoformat()
            self._conn.execute("UPDATE hosts_mac SET last_seen = ? WHERE mac = ?", (iso, mac))
            self._conn.execute("UPDATE hosts SET last_seen = ? WHERE mac = ?", (iso, mac))
            self._conn.commit()

    def list_hosts(self) -> list[dict]:
        """Optimierte Query: N+1 Problem behoben durch JOIN."""
        query = """
            SELECT h.mac, h.vendor, h.first_seen, h.last_seen,
                   (SELECT GROUP_CONCAT(ip, ', ') FROM hosts WHERE hosts.mac = h.mac) as ips,
                   (SELECT COUNT(e.id) FROM events e WHERE e.title LIKE '%' || h.mac || '%') as event_count
            FROM hosts_mac h
            ORDER BY h.last_seen DESC
        """
        return [{
            "mac": r[0], "vendor": r[1], "first_seen": r[2], 
            "last_seen": r[3], "ips": (r[4] or "").split(", "), "events": r[5]
        } for r in self._conn.execute(query).fetchall()]

    def write_evaluation(self, event_id: int, model: str, severity: int, category: str, explanation: str, raw: str = "{}", duration_ms: int = 0) -> None:
        self._conn.execute("INSERT OR REPLACE INTO event_evaluations VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (event_id, model, severity, category, explanation, raw, duration_ms, datetime.now(timezone.utc).isoformat()))
        self._conn.commit()

    def get_event_full(self, event_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT e.*, v.severity, v.category, v.explanation, v.model, v.duration_ms "
            "FROM events e LEFT JOIN event_evaluations v ON v.event_id = e.id WHERE e.id = ?", (event_id,)).fetchone()
        return {"id": row[0], "ts": row[1], "detector": row[2], "severity_hint": row[3], "title": row[4], 
                "src": row[5], "dst": row[6], "details": row[7], "llm_severity": row[8], 
                "llm_category": row[9], "llm_explanation": row[10], "llm_model": row[11], "llm_duration_ms": row[12]} if row else None

    def list_events_filtered(self, min_severity: int = 0, limit: int = 1000) -> list[dict]:
        rows = self._conn.execute("SELECT e.*, v.severity, v.category, v.explanation, v.model, v.duration_ms FROM events e LEFT JOIN event_evaluations v ON v.event_id = e.id ORDER BY e.id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "ts": r[1], "detector": r[2], "severity_hint": r[3], "title": r[4], "src": r[5], "dst": r[6], "details": r[7], "llm_severity": r[8], "llm_category": r[9], "llm_explanation": r[10], "llm_model": r[11], "llm_duration_ms": r[12]} for r in rows if (r[8] if r[8] is not None else r[3]) >= min_severity]

    def close(self) -> None:
        self._conn.close()