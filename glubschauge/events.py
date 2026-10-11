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

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # --- events --------------------------------------------------------

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

    # --- hosts (MAC/IP-Paare) ------------------------------------------

    def load_hosts(self) -> set[tuple[str, str]]:
        cur = self._conn.execute("SELECT mac, ip FROM hosts")
        return {(mac, ip) for mac, ip in cur.fetchall()}

    def load_macs(self) -> set[str]:
        """Alle bekannten MACs (für In-Memory-Cache im Detector)."""
        cur = self._conn.execute("SELECT mac FROM hosts_mac")
        return {row[0] for row in cur.fetchall()}

    def remember_host(self, mac: str, ip: str, ts: datetime) -> None:
        iso = ts.isoformat()
        self._conn.execute(
            "INSERT INTO hosts (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
            (mac, ip, iso, iso),
        )
        self._conn.commit()

    # --- hosts_mac (MAC-Stammdaten + Vendor) ---------------------------

    def has_mac(self, mac: str) -> bool:
        cur = self._conn.execute("SELECT 1 FROM hosts_mac WHERE mac = ?", (mac,))
        return cur.fetchone() is not None

    def upsert_mac(self, mac: str, vendor: str, ts: datetime) -> None:
        iso = ts.isoformat()
        self._conn.execute(
            "INSERT INTO hosts_mac (mac, vendor, first_seen, last_seen)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac) DO UPDATE SET last_seen = excluded.last_seen",
            (mac, vendor, iso, iso),
        )
        self._conn.commit()

    def touch_mac(self, mac: str, ts: datetime) -> None:
        """Nur last_seen aktualisieren – kein INSERT, kein Vendor-Update.

        Wird vom Detector gedrosselt aufgerufen (1x/30s pro MAC), damit der
        Online-Status im Dashboard live bleibt, ohne die DB zu fluten.
        """
        self._conn.execute(
            "UPDATE hosts_mac SET last_seen = ? WHERE mac = ?",
            (ts.isoformat(), mac),
        )
        self._conn.commit()

    def list_hosts(self) -> list[dict]:
        """Liefert alle bekannten MACs mit aggregierten IPs und Event-Zähler."""
        macs = self._conn.execute(
            "SELECT mac, vendor, first_seen, last_seen FROM hosts_mac"
            " ORDER BY last_seen DESC"
        ).fetchall()

        result: list[dict] = []
        for mac, vendor, first_seen, last_seen in macs:
            ip_rows = self._conn.execute(
                "SELECT ip, last_seen FROM hosts WHERE mac = ?"
                " ORDER BY (ip LIKE 'fe80:%') ASC, last_seen DESC",
                (mac,),
            ).fetchall()
            ips = [r[0] for r in ip_rows]
            event_count = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE title LIKE ?",
                (f"%({mac})%",),
            ).fetchone()[0]
            result.append({
                "mac": mac,
                "vendor": vendor,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "ips": ips,
                "events": event_count,
            })
        return result

    # --- LLM-Bewertungen -----------------------------------------------

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

    def list_events_filtered(self, min_severity: int = 0, limit: int = 1000) -> list[dict]:
        """Alle Events mit LLM-Bewertung, gefiltert nach effektiver Severity."""
        rows = self._conn.execute(
            """
            SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
                   e.src, e.dst, e.details_json,
                   v.severity, v.category, v.explanation, v.model, v.duration_ms
            FROM events e
            LEFT JOIN event_evaluations v ON v.event_id = e.id
            ORDER BY e.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        result: list[dict] = []
        for row in rows:
            llm_sev = row[8]
            effective = llm_sev if llm_sev is not None else row[3]
            if effective < min_severity:
                continue
            result.append({
                "id": row[0], "ts": row[1], "detector": row[2],
                "severity_hint": row[3], "title": row[4],
                "src": row[5], "dst": row[6], "details": row[7],
                "llm_severity": row[8], "llm_category": row[9],
                "llm_explanation": row[10], "llm_model": row[11],
                "llm_duration_ms": row[12],
            })
        return result

    def close(self) -> None:
        self._conn.close()