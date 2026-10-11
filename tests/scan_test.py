"""Löst Multi-Target-SYN-Scan gegen drei LAN-Ziele aus.

Warum drei Ziele?
    Windows' TCP-Stack cached "connection refused" pro (Ziel, Port)
    und drosselt SYN-Ausgaben an dasselbe Ziel, wenn die RST-Antwort
    noch im Stack liegt. Wenn man dieselben Ports auf drei verschiedene
    Ziele verteilt, umgeht man diesen Effekt und bekommt garantiert
    alle SYNs auf die Leitung.

Erwartetes Ergebnis:
    - syn_fan_out_multi feuert (>= 3 LAN-Ziele, > 5 Ports)
    - severity_hint 7 → Auto-Eskalation auf llama3.1:8b
    - DB-Eintrag: (N, 'llama3.1:8b', 7)

Zielwahl: nur Geräte, die immer antworten (Router + zwei feste Pis).
Nicht den eigenen PC scannen — der Traffic läuft über Loopback.
"""
import socket
import time

TARGETS = [
    "192.168.0.245",   # Pi ventosus
    "192.168.0.1",     # Router Vantiva
    "192.168.0.122",   # Pi inertia
]

PORTS = list(range(8000, 8010))   # 10 Ports pro Ziel → 30 SYNs gesamt
DELAY_BETWEEN_SYNS_S = 0.15       # 150 ms → Gesamtlaufzeit ~4,5 s
TIMEOUT_S = 0.25

sent     = 0
refused  = 0
opened   = []
errors   = 0

t0 = time.monotonic()

for target in TARGETS:
    for i, port in enumerate(PORTS):
        if i > 0 or target != TARGETS[0]:
            time.sleep(DELAY_BETWEEN_SYNS_S)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT_S)
        try:
            rc = s.connect_ex((target, port))
            sent += 1
            if rc == 0:
                opened.append((target, port))
            elif rc in (10061, 111):     # WSAECONNREFUSED / ECONNREFUSED
                refused += 1
            else:
                errors += 1
        except OSError:
            errors += 1
        finally:
            s.close()

dt = time.monotonic() - t0
print(f"{sent} SYNs an {len(TARGETS)} Ziele gesendet in {dt:.2f}s")
print(f"  offen:    {opened or '—'}")
print(f"  refused:  {refused}")
print(f"  errors:   {errors}")