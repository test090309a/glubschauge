"""Prüft, ob der high_volume-Detektor gefeuert hat."""
import sqlite3

c = sqlite3.connect("glubschauge.db")
rows = c.execute(
    "SELECT id, ts, detector, severity_hint, title "
    "FROM events WHERE detector = 'high_volume' "
    "ORDER BY id DESC LIMIT 5"
).fetchall()

if not rows:
    print("Keine high_volume-Events in der DB.")
    print("Prüfe:")
    print("  1. Läuft run.py?")
    print("  2. Steht volume_threshold_mb = 50.0 in config.toml?")
    print("  3. Wurde run.py nach der config-Änderung neu gestartet?")
else:
    for r in rows:
        print(r)