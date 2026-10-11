"""Verbindet Capture, Detektoren und Event-Store."""
from __future__ import annotations

import asyncio
import logging

from .capture import TSharkCapture
from .detectors import Detector
from .events import Event, EventStore

log = logging.getLogger(__name__)


class RuleEngine:
    def __init__(
        self,
        capture: TSharkCapture,
        detectors: list[Detector],
        store: EventStore,
        event_queue: asyncio.Queue | None = None,
        packet_queue: asyncio.Queue | None = None,
        ui_event_queue: asyncio.Queue | None = None,
    ) -> None:
        self.capture        = capture
        self.detectors      = detectors
        self.store          = store
        self.event_queue    = event_queue       # → LLM-Worker (2-Tupel)
        self.packet_queue   = packet_queue      # → TUI PacketTable
        self.ui_event_queue = ui_event_queue    # → TUI EventFeed (3-Tupel)
        self._processed     = 0

    async def run(self) -> None:
        try:
            async for pkt in self.capture.stream():
                self._processed += 1
                if self.packet_queue is not None:
                    try:
                        self.packet_queue.put_nowait(pkt)
                    except asyncio.QueueFull:
                        pass    # TUI kann nicht mithalten → Paket verwerfen

                for det in self.detectors:
                    try:
                        for ev in det.feed(pkt):
                            event_id = self.store.write(ev)
                            self._on_event(event_id, ev)
                    except Exception:
                        log.exception("Detektor %s warf Exception", det.name)
        finally:
            pass

    def _on_event(self, event_id: int, ev: Event) -> None:
        log.warning("EVENT #%d [%s sev=%d] %s",
                    event_id, ev.detector, ev.severity_hint, ev.title)

        # Queue 1: → LLM-Worker (erwartet 2-Tupel)
        if self.event_queue is not None:
            try:
                self.event_queue.put_nowait((event_id, ev))
            except asyncio.QueueFull:
                log.warning("Event-Queue voll, verwerfe #%d", event_id)

        # Queue 2: → TUI EventFeed (erwartet 3-Tupel, severity=None = neue Zeile)
        if self.ui_event_queue is not None:
            try:
                self.ui_event_queue.put_nowait((event_id, ev, None))
            except asyncio.QueueFull:
                pass

    @property
    def stats(self) -> dict:
        return {"processed": self._processed, "events": self.store.count()}