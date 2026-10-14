"""glubschauge — Einstiegspunkt TUI."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))


import asyncio
import logging
import logging.handlers


from glubschauge.capture     import TSharkCapture
from glubschauge.config      import load as load_config
from glubschauge.detectors   import (
    DnsFailureDetector, NewHostDetector, SynFanOutDetector,
    SynFanOutMultiDetector,
    BeaconingDetector, HighVolumeFlowDetector, ArpSpoofDetector,
)

from glubschauge.engine      import RuleEngine
from glubschauge.events      import EventStore
from glubschauge.llm         import OllamaClient
from glubschauge.ringbuffer  import RingBuffer
from glubschauge.tui         import GlubschaugeApp
from glubschauge.worker      import LlmWorker


# --- Pfade relativ zu run.py – funktioniert aus jedem CWD -------------
BASE_DIR    = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.toml"
DB_PATH     = BASE_DIR / "glubschauge.db"
LOG_PATH    = BASE_DIR / "glubschauge.log"
RING_DIR    = BASE_DIR / "ring"


# --- Logging mit Rotation ---------------------------------------------
def _setup_logging() -> logging.Logger:
    handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    return logging.getLogger("glubschauge")


log = _setup_logging()


def _excepthook(exc_type, exc_value, exc_tb) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    log.critical("Unbehandelte Exception:", exc_info=(exc_type, exc_value, exc_tb))


sys.excepthook = _excepthook


def main() -> None:
    cfg = load_config(CONFIG_PATH)

    capture = TSharkCapture(
        cfg.capture.tshark_path,
        cfg.capture.interface,
        cfg.capture.bpf_filter,
    )

    ringbuffer = None
    if cfg.ring.enabled:
        ring_filter = cfg.ring.bpf_filter or cfg.capture.bpf_filter
        ringbuffer = RingBuffer(
            tshark_path=cfg.capture.tshark_path,
            interface=cfg.capture.interface,
            bpf_filter=ring_filter,
            ring_dir=RING_DIR,
            file_interval_s=cfg.ring.file_interval_s,
            num_files=cfg.ring.num_files,
        )

    store = EventStore(DB_PATH)

    detectors = [
        NewHostDetector(
            store=store,
            local_subnets=cfg.network.local_subnets,
            trusted_macs=cfg.network.trusted_hosts,
            warmup_seconds=cfg.detectors.new_host_warmup_seconds,
        ),
        DnsFailureDetector(
            threshold=cfg.detectors.dns_failure_threshold,
            window_s=cfg.detectors.dns_failure_window_s,
            cooldown_s=cfg.detectors.dns_failure_cooldown_s,
        ),
        SynFanOutDetector(
            threshold=cfg.detectors.syn_fan_out_threshold,
            window_s=cfg.detectors.syn_fan_out_window_s,
            cooldown_s=cfg.detectors.syn_fan_out_cooldown_s,
            debug_first_n=15,
        ),
        SynFanOutMultiDetector(
            window_s=cfg.detectors.syn_fan_out_multi_window_s,
            min_targets=cfg.detectors.syn_fan_out_multi_min_targets,
            min_distinct_ports=cfg.detectors.syn_fan_out_multi_min_distinct_ports,
            cooldown_s=cfg.detectors.syn_fan_out_multi_cooldown_s,
            local_subnets=cfg.network.local_subnets,
        ),
        BeaconingDetector(
            min_samples=cfg.detectors.beaconing_min_samples,
            max_jitter_cv=cfg.detectors.beaconing_max_jitter_cv,
            window_minutes=cfg.detectors.beaconing_window_minutes,
        ),
        HighVolumeFlowDetector(
            threshold_mb=cfg.detectors.volume_threshold_mb,
            window_s=cfg.detectors.volume_window_s,
        ),
        ArpSpoofDetector(
            target_ip="192.168.0.1", # Deine Router-IP
            target_mac="00:11:22:33:44:55" # Die echte MAC deines Routers
        ),
    ]

    llm_queue      = asyncio.Queue(maxsize=100)
    packet_queue   = asyncio.Queue(maxsize=500)
    ui_event_queue = asyncio.Queue(maxsize=200)

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
        llm_config=cfg.llm,
        local_subnets=cfg.network.local_subnets,
    )

    app = GlubschaugeApp(
        engine=engine,
        worker=worker,
        capture=capture,
        ringbuffer=ringbuffer,
        reports_dir=BASE_DIR / "reports",
    )
    app.run()


if __name__ == "__main__":
    # Wir leiten stderr in eine Datei um, um den "blitzartigen" Fehler zu sehen
    with open("crash_log.txt", "w") as f:
        sys.stderr = f
        try:
            main()
        except Exception:
            # Hier wird der Traceback in die Datei geschrieben
            import traceback
            traceback.print_exc()
            raise