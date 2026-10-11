"""Phase 4b: glubschauge mit TUI, Detail-Panel und Wireshark-Sprung."""
import asyncio
import logging
from pathlib import Path

from glubschauge.capture     import TSharkCapture
from glubschauge.config      import load as load_config
from glubschauge.detectors   import (
    DnsFailureDetector, NewHostDetector, SynFanOutDetector,
)
from glubschauge.engine      import RuleEngine
from glubschauge.events      import EventStore
from glubschauge.llm         import OllamaClient
from glubschauge.ringbuffer  import RingBuffer
from glubschauge.tui         import GlubschaugeApp
from glubschauge.worker      import LlmWorker

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename="glubschauge.log",
)
log = logging.getLogger(__name__)

DB_PATH = Path("glubschauge.db")


def main() -> None:
    cfg = load_config("config.toml")

    # --- Capture (Haupt-tshark, strukturierte Metadaten) -------------
    capture = TSharkCapture(
        cfg.capture.tshark_path,
        cfg.capture.interface,
        cfg.capture.bpf_filter,
    )

    # --- Ringpuffer (zweiter tshark, rohe pcapng-Files) --------------
    ringbuffer = None
    if cfg.ring.enabled:
        ring_filter = cfg.ring.bpf_filter or cfg.capture.bpf_filter
        ringbuffer = RingBuffer(
            tshark_path=cfg.capture.tshark_path,
            interface=cfg.capture.interface,
            bpf_filter=ring_filter,
            ring_dir=cfg.ring.ring_dir,
            file_interval_s=cfg.ring.file_interval_s,
            num_files=cfg.ring.num_files,
        )

    # --- Persistenz ---------------------------------------------------
    store = EventStore(DB_PATH)

    # --- Detektoren ---------------------------------------------------
    detectors = [
        NewHostDetector(
            store=store,
            local_subnets=cfg.network.local_subnets,
            trusted_macs=cfg.network.trusted_hosts,
            warmup_seconds=cfg.detectors.new_host_warmup_seconds,
        ),
        DnsFailureDetector(),
        SynFanOutDetector(),
    ]

    # --- Queues -------------------------------------------------------
    llm_queue      = asyncio.Queue(maxsize=100)
    packet_queue   = asyncio.Queue(maxsize=500)
    ui_event_queue = asyncio.Queue(maxsize=200)

    # --- Engine + LLM-Worker -----------------------------------------
    engine = RuleEngine(
        capture, detectors, store,
        event_queue=llm_queue,
        packet_queue=packet_queue,
        ui_event_queue=ui_event_queue,
    )
    client = OllamaClient()
    worker = LlmWorker(
        llm_queue, store, client,
        stage="filter",
        ui_event_queue=ui_event_queue,
    )

    # --- TUI ----------------------------------------------------------
    app = GlubschaugeApp(
        engine=engine,
        worker=worker,
        capture=capture,
        ringbuffer=ringbuffer,
    )
    app.run()   # Textual startet den Loop, on_mount() startet alle Tasks


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")