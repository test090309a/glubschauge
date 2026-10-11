"""Datenmodelle für glubschauge."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Packet:
    """Ein einzelnes, aus tshark extrahiertes Paket."""
    frame_number: int
    timestamp: datetime
    src: str
    dst: str
    protocol: str          # oberstes Protokoll, z.B. "tls", "dns", "arp"
    protocols: list[str]   # gesamte Kette, z.B. ["eth", "ip", "tcp", "tls"]
    length: int
    src_port: int | None = None
    dst_port: int | None = None
    info: str = ""
    raw: dict[str, Any] = field(default_factory=dict)  # Original-JSON für tiefe Analyse

    def summary(self) -> str:
        """Kurze, einzeilige Zusammenfassung fürs TUI."""
        if self.src_port is not None and self.dst_port is not None:
            endpoints = f"{self.src}:{self.src_port} → {self.dst}:{self.dst_port}"
        elif self.src_port is not None:
            endpoints = f"{self.src}:{self.src_port} → {self.dst}"
        else:
            endpoints = f"{self.src} → {self.dst}"
        return f"#{self.frame_number:>6} {self.protocol:<8} {endpoints} ({self.length}B)"