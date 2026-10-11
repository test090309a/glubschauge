"""Datenzugriffsschicht für das Dashboard."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).resolve().parent.parent / "glubschauge.db"

_conn: sqlite3.Connection | None = None


def host_status(last_seen_iso: str) -> tuple[str, str]:
    """Liefert (status, color) aus last_seen-ISO-String."""
    if not last_seen_iso:
        return ("offline", "#6c757d")
    try:
        ts = pd.Timestamp(last_seen_iso)
        if ts.tzinfo is None:
            ts = ts.tz_localize("UTC")
        delta = (pd.Timestamp.now(tz="UTC") - ts).total_seconds()
    except Exception:
        return ("offline", "#6c757d")

    if delta < 120:      return ("online",  "#28a745")
    if delta < 900:      return ("idle",    "#ffc107")
    return ("offline", "#6c757d")

def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.row_factory = sqlite3.Row
    return _conn


def _iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


# --- KPIs ----------------------------------------------------------------

def get_kpis() -> dict:
    conn = get_connection()
    cutoff_24h = _iso_hours_ago(24)
    cutoff_1h  = _iso_hours_ago(1)

    active_hosts = conn.execute(
        "SELECT COUNT(DISTINCT mac) FROM hosts WHERE last_seen >= ?",
        (cutoff_1h,),
    ).fetchone()[0]

    events_24h = conn.execute(
        "SELECT COUNT(*) FROM events WHERE ts >= ?",
        (cutoff_24h,),
    ).fetchone()[0]

    critical_events = conn.execute(
        """SELECT COUNT(*) FROM events e
           LEFT JOIN event_evaluations v ON v.event_id = e.id
           WHERE e.ts >= ?
             AND COALESCE(v.severity, e.severity_hint) >= 6""",
        (cutoff_24h,),
    ).fetchone()[0]

    new_hosts = conn.execute(
        "SELECT COUNT(*) FROM events WHERE ts >= ? AND detector = 'new_host'",
        (cutoff_24h,),
    ).fetchone()[0]

    return {
        "active_hosts":     active_hosts,
        "events_24h":       events_24h,
        "critical_events":  critical_events,
        "new_hosts_24h":    new_hosts,
    }


# --- Events ---------------------------------------------------------------

def get_recent_events(limit: int = 20) -> pd.DataFrame:
    conn = get_connection()
    return pd.read_sql_query(
        """
        SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
               e.src, e.dst, e.details_json,
               v.severity AS llm_severity, v.category, v.explanation,
               v.model, v.duration_ms
        FROM events e
        LEFT JOIN event_evaluations v ON v.event_id = e.id
        ORDER BY e.id DESC
        LIMIT ?
        """,
        conn, params=(limit,),
    )


def get_events_filtered(min_severity: int = 0, detector: str | None = None,
                        limit: int = 200) -> pd.DataFrame:
    conn = get_connection()
    q = """
        SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
               e.src, e.dst, e.details_json,
               v.severity AS llm_severity, v.category, v.explanation,
               v.model, v.duration_ms
        FROM events e
        LEFT JOIN event_evaluations v ON v.event_id = e.id
        WHERE COALESCE(v.severity, e.severity_hint) >= ?
    """
    params: list = [min_severity]
    if detector and detector != "alle":
        q += " AND e.detector = ?"
        params.append(detector)
    q += " ORDER BY e.id DESC LIMIT ?"
    params.append(limit)
    return pd.read_sql_query(q, conn, params=tuple(params))


def get_detector_names() -> list[str]:
    conn = get_connection()
    rows = conn.execute("SELECT DISTINCT detector FROM events ORDER BY detector").fetchall()
    return ["alle"] + [r[0] for r in rows]


# --- Statistiken ----------------------------------------------------------

def get_severity_distribution() -> pd.DataFrame:
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT COALESCE(v.severity, e.severity_hint) AS sev, COUNT(*) AS count
        FROM events e
        LEFT JOIN event_evaluations v ON v.event_id = e.id
        GROUP BY sev
        ORDER BY sev
        """,
        conn,
    )
    return df


def get_top_hosts(limit: int = 10) -> pd.DataFrame:
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT h.vendor, h.mac, COUNT(e.id) AS event_count
        FROM hosts_mac h
        LEFT JOIN events e ON e.title LIKE '%' || h.mac || '%'
        GROUP BY h.mac
        HAVING event_count > 0
        ORDER BY event_count DESC
        LIMIT ?
        """,
        conn, params=(limit,),
    )
    return df


def get_event_timeline(hours: int = 24) -> pd.DataFrame:
    conn = get_connection()
    cutoff = _iso_hours_ago(hours)
    df = pd.read_sql_query(
        "SELECT ts, detector FROM events WHERE ts >= ?",
        conn, params=(cutoff,),
    )
    if df.empty:
        return pd.DataFrame(columns=["hour", "detector", "count"])

    # Robust gegen pandas 3.0:
    #   1. explizit parsen mit errors="coerce"
    #   2. tz-aware → tz-naive konvertieren (Plotly arbeitet lieber naiv)
    #   3. erst dann flooren
    df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")
    df = df.dropna(subset=["ts"]).copy()
    if df.empty:
        return pd.DataFrame(columns=["hour", "detector", "count"])

    df["hour"] = (
        df["ts"]
        .dt.tz_convert("UTC")
        .dt.tz_localize(None)
        .dt.floor("h")
    )

    grouped = (
        df.groupby(["hour", "detector"], as_index=False)
        .size()
        .rename(columns={"size": "count"})
    )
    return grouped


# --- Hosts ----------------------------------------------------------------

def get_hosts() -> pd.DataFrame:
    conn = get_connection()
    df = pd.read_sql_query(
        """
        SELECT h.mac, h.vendor, h.first_seen, h.last_seen,
               (SELECT GROUP_CONCAT(ip, ', ')
                  FROM hosts WHERE hosts.mac = h.mac) AS ips,
               (SELECT COUNT(*) FROM hosts WHERE hosts.mac = h.mac) AS ip_count,
               (SELECT COUNT(*) FROM events
                  WHERE events.title LIKE '%' || h.mac || '%') AS event_count
        FROM hosts_mac h
        ORDER BY h.last_seen DESC
        """,
        conn,
    )
    # Status + Farbe pro Zeile berechnen
    statuses = df["last_seen"].apply(host_status)
    df["status"]       = [s[0] for s in statuses]
    df["status_color"] = [s[1] for s in statuses]
    return df


def get_topology_elements() -> list[dict]:
    conn = get_connection()
    hosts = conn.execute(
        """
        SELECT h.mac, h.vendor, h.last_seen,
               (SELECT ip FROM hosts WHERE hosts.mac = h.mac
                  ORDER BY last_seen DESC LIMIT 1) AS primary_ip
        FROM hosts_mac h
        """
    ).fetchall()

    elements: list[dict] = [{
        "data": {"id": "router", "label": "Router", "type": "router"},
        "classes": "router",
    }]

    for mac, vendor, last_seen, ip in hosts:
        status, _ = host_status(last_seen)
        node_id = mac or (ip or "unknown")
        label = f"{vendor or 'Unbekannt'}\n{ip or mac}"
        elements.append({
            "data": {
                "id": node_id,
                "label": label,
                "vendor": vendor or "",
                "status": status,
            },
            "classes": f"host {status}",
        })
        elements.append({
            "data": {"source": node_id, "target": "router"},
            "classes": f"link {status}",
        })
    return elements