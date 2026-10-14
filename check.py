import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from glubschauge.capture import TSharkCapture
    from glubschauge.detectors import ArpSpoofDetector
    from glubschauge.events import EventStore
    print("Alle Module erfolgreich geladen!")
except Exception as e:
    print(f"IMPORT FEHLER: {e}")