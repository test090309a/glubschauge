"""Simuliert Beaconing: wiederholt kurze Verbindungen zu einem externen Host.

Alle 6 Sekunden ein neuer TCP-Connect zu 1.1.1.1:443. Der Beaconing-Detektor
zählt SYN-Pakete pro (src, dst), berechnet das mittlere Intervall und den
CV (Variationskoeffizient). Bei konstantem Intervall ist CV ≈ 0 → Alarm.

Warum 1.1.1.1? 
    - Externer Host, Traffic geht über die echte Netzwerkkarte.
    - Antwortet auf Port 443 zuverlässig (kein Firewall-Blocking).
    - Fest (DNS-Auflösung nicht nötig).

Dauer: (samples - 1) * interval ≈ 30 s bei 5 Samples × 6 s.
"""
import socket
import time
from datetime import datetime

TARGET     = "1.1.1.1"
PORT       = 443
INTERVAL_S = 6
SAMPLES    = 6

print(f"Beacon-Simulation: {SAMPLES} Verbindungen alle {INTERVAL_S}s "
      f"an {TARGET}:{PORT}")
print(f"Gesamtdauer: ca. {(SAMPLES - 1) * INTERVAL_S}s\n")

for i in range(SAMPLES):
    t0 = time.monotonic()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((TARGET, PORT))
        result = "connected"
    except socket.timeout:
        result = "timeout"
    except OSError as e:
        result = f"error {e.errno}"
    finally:
        s.close()

    now = datetime.now().strftime("%H:%M:%S")
    print(f"  [{i+1:2d}/{SAMPLES}] {now}  {result}")

    if i < SAMPLES - 1:
        elapsed = time.monotonic() - t0
        remaining = INTERVAL_S - elapsed
        if remaining > 0:
            time.sleep(remaining)

print("\nFertig. Jetzt 5 s warten und DB prüfen:")
print('  python -c "import sqlite3; c=sqlite3.connect(\'glubschauge.db\'); '
      'print(*c.execute(\'SELECT id, detector, severity_hint, title FROM events '
      'WHERE detector=\\\'beaconing\\\' ORDER BY id DESC LIMIT 3\').fetchall(), sep=\'\\n\')"')