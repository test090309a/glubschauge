"""tshark-Live-Capture als async Iterator."""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from .models import Packet

log = logging.getLogger(__name__)


class TSharkCapture:
    """Startet tshark als Subprozess und liefert geparste Packets als AsyncIterator."""

    def __init__(
        self,
        tshark_path: str | Path,
        interface: str,
        bpf_filter: str = "",
    ) -> None:
        self.tshark_path = str(tshark_path)
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._proc: subprocess.Popen | None = None
        self._restart_count = 0

    def _build_cmd(self) -> list[str]:
        cmd = [
            self.tshark_path,
            "-i", self.interface,
            "-l",                 # line-buffered → sofortige Ausgabe
            "-T", "ek",           # Elasticsearch-JSON, 2 Zeilen pro Paket
            "-n",                 # keine Namensauflösung → spart CPU/Zeit
            "-q",                 # weniger Statusausgaben auf stderr
        ]
        if self.bpf_filter:
            cmd += ["-f", self.bpf_filter]
        return cmd

    def _start(self) -> subprocess.Popen:
        cmd = self._build_cmd()
        log.info("Starte tshark: %s", " ".join(cmd))
        creationflags = 0x08000000 if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )

    async def stream(self) -> AsyncIterator[Packet]:
        """Endlos-Iterator. Startet tshark bei Absturz automatisch neu."""
        while True:
            self._proc = self._start()
            try:
                async for pkt in self._read_stream():
                    yield pkt
            except Exception as e:
                log.exception("Capture-Stream abgebrochen: %s", e)
            finally:
                self._shutdown_proc()

            self._restart_count += 1
            if self._restart_count > 10:
                raise RuntimeError("tshark zu oft abgestürzt – Abbruch.")
            await asyncio.sleep(2)  # Backoff vor Neustart

    async def _read_stream(self) -> AsyncIterator[Packet]:
        assert self._proc and self._proc.stdout
        stdout = self._proc.stdout
        loop = asyncio.get_running_loop()

        while True:
            line = await loop.run_in_executor(None, stdout.readline)
            if not line:
                return
            line = line.strip()
            if not line:
                continue

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                log.debug("Nicht-JSON-Zeile ignoriert: %r", line[:80])
                continue

            # tshark -T ek gibt abwechselnd Index-Header und Paket-JSON aus.
            if "index" in obj:
                continue

            pkt = self._parse_packet(obj)
            if pkt is not None:
                yield pkt

    @staticmethod
    def _parse_packet(obj: dict) -> Packet | None:
        """Wandelt das ek-JSON in ein Packet-Objekt um."""
        layers: dict = obj.get("layers", {})
        frame = layers.get("frame", {})
        if not frame:
            return None

        try:
            frame_number = int(frame.get("frame_frame_number", 0))
            length = int(frame.get("frame_frame_len", 0))
        except (TypeError, ValueError):
            return None

        ts_str = frame.get("frame_frame_time_utc") or frame.get("frame_frame_time")
        timestamp = _parse_iso_utc(ts_str)

        protocols_str = frame.get("frame_frame_protocols", "")
        raw_protocols = protocols_str.split(":") if protocols_str else []
        protocols = _normalize_protocols(raw_protocols)

        # Prioritätsliste: konkrete App-Protokolle zuerst, dann L4, dann L3.
        priority = [
            "tls", "https", "http", "ssh", "ftp", "smtp", "dns", "quic",
            "dhcp", "ntp", "mdns", "ssdp", "igmp", "arp",
            "icmp", "icmpv6",
            "tcp", "udp",
            "ipv6", "ip",
        ]
        top = next((p for p in priority if p in protocols), None)

        # Fallback 1: irgendein nicht-triviales Protokoll aus der Kette
        if top is None:
            for p in reversed(protocols):
                if p not in {"eth", "ethertype", "data"}:
                    top = p
                    break

        # Fallback 2: L4 direkt aus den Layern raten
        if top is None:
            if "tcp" in layers:
                top = "tcp"
            elif "udp" in layers:
                top = "udp"
            elif "icmp" in layers or "icmpv6" in layers:
                top = "icmp"
            elif "arp" in layers:
                top = "arp"

        if top is None:
            top = "unknown"

        src, dst, sport, dport = _extract_endpoints(layers)

        return Packet(
            frame_number=frame_number,
            timestamp=timestamp,
            src=src,
            dst=dst,
            protocol=top,
            protocols=protocols,
            length=length,
            src_port=sport,
            dst_port=dport,
            raw=layers,
        )

    def _shutdown_proc(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        finally:
            self._proc = None

    def stop(self) -> None:
        if self._proc is None:
            return
        self._shutdown_proc()


# --- Hilfsfunktionen -------------------------------------------------------

def _normalize_protocols(raw: list[str]) -> list[str]:
    """Normalisiert die Protokoll-Kette aus tshark.

    - "tcp.options" → "tcp"
    - "tls.record"  → "tls"
    - Duplikate entfernen, Reihenfolge bleibt erhalten.

    Beispiel:
        ["eth", "ethertype", "ip", "tcp", "tcp.options"]
        → ["eth", "ethertype", "ip", "tcp"]
    """
    out: list[str] = []
    seen: set[str] = set()
    for p in raw:
        base = p.split(".")[0] if p else ""
        if not base:
            continue
        if base in seen:
            continue
        out.append(base)
        seen.add(base)
    return out


def _parse_iso_utc(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _extract_endpoints(layers: dict) -> tuple[str, str, int | None, int | None]:
    """Zieht src/dst/ports aus IP-, IPv6- oder ARP-Layern."""
    ip = layers.get("ip") or layers.get("ipv6") or {}
    arp = layers.get("arp") or {}
    eth = layers.get("eth") or {}

    src = (
        ip.get("ip_ip_src")
        or ip.get("ipv6_ipv6_src")
        or arp.get("arp_arp_src_proto_ipv4")
        or eth.get("eth_eth_src", "?")
    )
    dst = (
        ip.get("ip_ip_dst")
        or ip.get("ipv6_ipv6_dst")
        or arp.get("arp_arp_dst_proto_ipv4")
        or eth.get("eth_eth_dst", "?")
    )

    tcp = layers.get("tcp") or {}
    udp = layers.get("udp") or {}

    sport = _to_int(tcp.get("tcp_tcp_srcport") or udp.get("udp_udp_srcport"))
    dport = _to_int(tcp.get("tcp_tcp_dstport") or udp.get("udp_udp_dstport"))

    return src, dst, sport, dport


def _to_int(v) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None