"""Datenzugriffsschicht für das Dashboard."""
from __future__ import annotations

import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd  # type: ignore[import-not-found]

DB_PATH = Path(__file__).resolve().parent.parent / "glubschauge.db"

_conn: sqlite3.Connection | None = None


# --- Status-Logik ---------------------------------------------------------

def host_status(last_seen_iso: str) -> tuple[str, str]:
    if not last_seen_iso:
        return ("offline", "#6c757d")
    try:
        s = str(last_seen_iso).strip().replace("Z", "+00:00")
        ts = datetime.fromisoformat(s)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        
        # Berechnung: Sekunden seit dem letzten Kontakt
        delta = (datetime.now(timezone.utc) - ts).total_seconds()
    except Exception:
        return ("offline", "#6c757d")

    # ERWEITERTES FENSTER:
    # 0 - 600s (10 min) = Online (Grün)
    # 600 - 3600s (1 Stunde) = Idle (Gelb)
    # Alles darüber = Offline (Grau)
    if delta < 600:   return ("online",  "#28a745")
    if delta < 3600:  return ("idle",    "#ffc107")
    return ("offline", "#6c757d")


def _iso_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.row_factory = sqlite3.Row
    return _conn


# --- KPIs ----------------------------------------------------------------

def get_kpis() -> dict:
    conn = get_connection()
    cutoff_24h = _iso_hours_ago(24)
    cutoff_1h  = _iso_hours_ago(1)

    active_hosts = conn.execute(
        "SELECT COUNT(*) FROM hosts_mac WHERE last_seen >= ?",
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
    """Optimierte Query für das Dashboard."""
    conn = get_connection()
    # Verwendet die bereits optimierte Logik aus EventStore/Event-Logik
    query = """
        SELECT h.mac, h.vendor, h.first_seen, h.last_seen,
               (SELECT GROUP_CONCAT(ip, ', ') FROM hosts WHERE hosts.mac = h.mac) AS ips,
               (SELECT COUNT(*) FROM events WHERE events.title LIKE '%' || h.mac || '%') AS event_count
        FROM hosts_mac h
        ORDER BY h.last_seen DESC
    """
    df = pd.read_sql_query(query, conn)
    statuses = df["last_seen"].apply(host_status)
    df["status"]       = [s[0] for s in statuses]
    df["status_color"] = [s[1] for s in statuses]
    return df


# --- Topologie ------------------------------------------------------------

def _short_vendor(vendor: str, mac: str) -> str:
    """Kürzt lange Vendor-Namen für die Graph-Labels."""
    v = (vendor or "").strip()
    # Klammerzusätze wie "(Router)" entfernen
    if "(" in v:
        v = v.split("(")[0].strip()
    # Umlaute / zu lange Namen kürzen
    if len(v) > 18:
        v = v[:16] + "…"
    if not v:
        v = mac[:11] if mac else "Unbekannt"
    return v


def _short_ip(ip: str | None) -> str:
    """Kürzt sehr lange Adressen fürs Label."""
    if not ip:
        return "—"
    if len(ip) > 24:
        return ip[:22] + "…"
    return ip


def get_topology_elements() -> list[dict]:
    """Liefert Cytoscape-Elemente mit **stabilen Positionen**.

    Der Router sitzt im Ursprung (0,0), die Hosts werden auf einem Kreis
    verteilt. Dadurch kann das Dashboard das `preset`-Layout verwenden –
    ohne Physik-Simulation und ohne Springen bei jedem Refresh.
    """
    conn = get_connection()
    hosts = conn.execute(
        """
        SELECT h.mac, h.vendor, h.last_seen,
               (SELECT ip FROM hosts WHERE hosts.mac = h.mac
                  ORDER BY (ip LIKE 'fe80:%') ASC, last_seen DESC LIMIT 1) AS primary_ip
        FROM hosts_mac h
        ORDER BY h.mac
        """
    ).fetchall()

    elements: list[dict] = [{
        "data": {"id": "router", "label": "Router", "type": "router"},
        "classes": "router",
        "position": {"x": 0, "y": 0},
    }]

    n = len(hosts)
    if n == 0:
        return elements

    radius = 200 if n <= 12 else 260

    for i, (mac, vendor, last_seen, ip) in enumerate(hosts):
        if vendor and "(router)" in vendor.lower():
            continue  # Router ist bereits das Zentrum
        status, _ = host_status(last_seen)
        node_id = mac or (ip or f"unknown-{i}")
        label_name = _short_vendor(vendor, mac)
        label_ip   = _short_ip(ip)
        label = f"{label_name}\n{label_ip}"

        # Kreis, Start oben (-90°), im Uhrzeigersinn
        angle = (2 * math.pi * i / n) - (math.pi / 2)
        x = radius * math.cos(angle)
        y = radius * math.sin(angle)

        elements.append({
            "data": {
                "id":        node_id,
                "label":     label,
                "vendor":    vendor or "",
                "ip":        ip or "",
                "mac":       mac or "",
                "status":    status,
                "tooltip":   f"{vendor or 'Unbekannt'}\n{mac}\n{ip or '—'}",
            },
            "classes":  f"host {status}",
            "position": {"x": x, "y": y},
        })
        elements.append({
            "data": {"source": node_id, "target": "router"},
            "classes": f"link {status}",
        })
    return elements

# --------------------------------
#  Host-Details (Ports, Events)
# --------------------------------

def get_host_details(mac: str) -> dict | None:
    """Holt alle Details, offene Ports und Events für einen spezifischen Rechner."""
    conn = get_connection()
    if not mac:
        return None

    # 1. Basis-Hostdaten
    row = conn.execute(
        """SELECT h.mac, h.vendor, h.first_seen, h.last_seen,
                  (SELECT GROUP_CONCAT(ip, ', ') FROM hosts WHERE hosts.mac = h.mac) AS ips
           FROM hosts_mac h
           WHERE h.mac = ?""",
        (mac,),
    ).fetchone()

    if not row:
        return None

    status, color = host_status(row["last_seen"])

    # 2. Erkannte offene Ports & Dienste
    ports_cur = conn.execute(
        "SELECT port, proto, service, last_seen FROM host_ports WHERE mac = ? ORDER BY port ASC",
        (mac,),
    ).fetchall()
    ports = [dict(r) for r in ports_cur]

    # 3. Sicherheits-Events zu diesem Host
    events_cur = conn.execute(
        """SELECT e.id, e.ts, e.detector, COALESCE(v.severity, e.severity_hint) as sev, e.title
           FROM events e
           LEFT JOIN event_evaluations v ON v.event_id = e.id
           WHERE e.src = ? OR e.dst = ? OR e.title LIKE '%' || ? || '%'
           ORDER BY e.id DESC LIMIT 10""",
        (row["ips"] or "", row["ips"] or "", mac),
    ).fetchall()
    events = [dict(r) for r in events_cur]

    return {
        "mac": row["mac"],
        "vendor": row["vendor"] or "Unbekannt",
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "status": status,
        "status_color": color,
        "ips": (row["ips"] or "—").split(", "),
        "ports": ports,
        "events": events,
    }