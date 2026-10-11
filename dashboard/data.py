# dashboard/data.py
import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "glubschauge.db"

def get_connection():
    # Eine einzige Verbindung, die wiederverwendet wird.
    if not hasattr(get_connection, "_conn"):
        get_connection._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        # WAL-Modus für bessere Parallelität (Lesen während Schreiben)
        get_connection._conn.execute("PRAGMA journal_mode=WAL;")
    return get_connection._conn

def get_recent_events(limit=50):
    # Holt die neuesten Events für das Dashboard
    conn = get_connection()
    query = """
        SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
               v.severity AS llm_severity, v.category, v.explanation
        FROM events e
        LEFT JOIN event_evaluations v ON v.event_id = e.id
        ORDER BY e.id DESC
        LIMIT ?
    """
    return pd.read_sql_query(query, conn, params=(limit,))

def get_host_inventory():
    # Aggregiert Host-Daten für die Inventar-Ansicht
    conn = get_connection()
    query = """
        SELECT mac, vendor, first_seen, last_seen,
               (SELECT COUNT(*) FROM hosts WHERE hosts.mac = hosts_mac.mac) AS ip_count,
               (SELECT COUNT(*) FROM events WHERE events.title LIKE '%' || hosts_mac.mac || '%') AS event_count
        FROM hosts_mac
        ORDER BY last_seen DESC
    """
    return pd.read_sql_query(query, conn)

# ... weitere Funktionen für Charts, Statistiken etc.