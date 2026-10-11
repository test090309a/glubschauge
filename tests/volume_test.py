"""Löst High-Volume-Flow aus: schneller Download über HTTPS.

Lädt 100 MB von nbg1-speed.hetzner.com (offizieller Speedtest-Endpunkt).
Bei 50 MB in 60 s (Test-Schwelle) feuert der Detektor.

Hinweis: `volume_threshold_mb = 50.0` sollte in config.toml gesetzt sein.
"""
import os
import time
import urllib.request

# Neue, zuverlässigere URL
URL = "https://nbg1-speed.hetzner.com/100MB.bin" 
CHUNK = 1024 * 1024           # 1 MB
SINK = os.devnull

print(f"Downloade {URL}")
print("Test-Schwelle in config.toml: volume_threshold_mb = 50.0\n")

start = time.monotonic()
total = 0

# Der User-Agent wird beibehalten, um Blockierungen zu vermeiden.
req = urllib.request.Request(
    URL,
    headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "glubschauge-test",
    },
)

try:
    with urllib.request.urlopen(req, timeout=30) as resp, open(SINK, "wb") as sink:
        while True:
            chunk = resp.read(CHUNK)
            if not chunk:
                break
            sink.write(chunk)
            total += len(chunk)
            elapsed = time.monotonic() - start
            rate = total / elapsed / (1024 * 1024) if elapsed > 0 else 0
            print(f"\r  {total / (1024*1024):7.1f} MB  |  "
                  f"{rate:6.1f} MB/s  |  {elapsed:5.1f}s",
                  end="")
except Exception as e:
    print(f"\n\nDownload abgebrochen: {type(e).__name__}: {e}")

dt = time.monotonic() - start
rate = total / dt / (1024 * 1024) if dt > 0 else 0
print(f"\n\nFertig: {total / (1024*1024):.1f} MB in {dt:.1f}s "
      f"({rate:.1f} MB/s)")