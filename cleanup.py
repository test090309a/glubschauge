"""Einmalig: high_volume-Müll aus der DB entfernen."""
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent / "glubschauge.db"
c = sqlite3.connect(DB)
n_before = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
c.execute("DELETE FROM events WHERE detector = 'high_volume'")
c.execute("DELETE FROM event_evaluations WHERE event_id NOT IN (SELECT id FROM events)")
c.commit()
n_after = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
print(f"Events: {n_before} → {n_after}  (gelöscht: {n_before - n_after})")
c.close()