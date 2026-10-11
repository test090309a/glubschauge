"""Regelbasierte Detektoren – die 'billige' Vorstufe zum LLM."""
from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Iterable

from .events import Event, EventStore
from .models import Packet

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Basisklasse
# ---------------------------------------------------------------------------

class Detector(ABC):
    """Basisklasse. Bekommt jedes Paket, gibt 0..n Events aus."""
    name: str = "base"

    @abstractmethod
    def feed(self, pkt: Packet) -> Iterable[Event]:
        ...


# ---------------------------------------------------------------------------
# Helfer
# ---------------------------------------------------------------------------

def _icmp_layer(pkt: Packet) -> dict:
    return pkt.raw.get("icmp") or pkt.raw.get("icmpv4") or {}


def _tcp_flags(pkt: Packet) -> set[str]:
    """Liefert eine Menge von Flag-Namen, z. B. {'syn'} oder {'syn','ack'}."""
    tcp = pkt.raw.get("tcp") or {}

    # Variante A: tshark gibt einen String wie "Syn" oder "Syn, Ack"
    s = tcp.get("tcp_tcp_flags_str") or tcp.get("tcp_tcp_flags_tree_..."
                                              if False else None)
    if isinstance(s, str) and s:
        return {p.strip().lower() for p in s.replace(",", "+").split("+") if p.strip()}

    # Variante B: Rohwert als int oder Hex-String
    raw = tcp.get("tcp_tcp_flags")
    if raw is None:
        return set()
    try:
        if isinstance(raw, str):
            v = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw)
        else:
            v = int(raw)
    except (TypeError, ValueError):
        return set()

    flags: set[str] = set()
    if v & 0x01: flags.add("fin")
    if v & 0x02: flags.add("syn")
    if v & 0x04: flags.add("rst")
    if v & 0x08: flags.add("psh")
    if v & 0x10: flags.add("ack")
    if v & 0x20: flags.add("urg")
    return flags


# ---------------------------------------------------------------------------
# Detektor 1: neuer Host im LAN
# ---------------------------------------------------------------------------

class NewHostDetector(Detector):
    """Erkennt MAC/IP-Paare im lokalen LAN, die noch nie gesehen wurden.

    Nur Pakete, deren Source-IP in einem lokalen Subnetz liegt, werden
    berücksichtigt. Transit-Pakete (Router forwarded externe Antworten)
    werden dadurch ignoriert – genau der Bug, der im ersten Lauf 30
    falsche Events produziert hat.
    """

    name = "new_host"

    def __init__(
        self,
        store: EventStore,
        local_subnets: list[str],
        trusted_macs: list[str] | None = None,
        warmup_seconds: int = 60,
    ) -> None:
        self.store       = store
        self.subnets     = [ipaddress.ip_network(s) for s in local_subnets]
        self.trusted     = {m.lower() for m in (trusted_macs or [])}
        self.warmup_end  = datetime.now(timezone.utc) + timedelta(seconds=warmup_seconds)
        # Aus DB laden, damit Neustart nicht alles erneut als "neu" meldet
        self._known: set[tuple[str, str]] = store.load_hosts()

    def _is_local(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        return any(ip in net for net in self.subnets)

    def feed(self, pkt: Packet):
        eth = pkt.raw.get("eth") or {}
        mac = (eth.get("eth_eth_src") or "").lower()
        ip  = pkt.src

        if not mac or not ip or ip == "?":
            return
        if mac.startswith(("01:", "33:", "ff:")):     # Multicast/Broadcast-MAC
            return
        if not self._is_local(ip):
            return

        key = (mac, ip)
        if key in self._known:
            return

        self._known.add(key)
        self.store.remember_host(mac, ip, pkt.timestamp)

        # Lernphase: nur lernen, nichts alarmieren
        if datetime.now(timezone.utc) < self.warmup_end:
            return

        # Vertrauenswürdige MACs nie alarmieren
        if mac in self.trusted:
            return

        yield Event(
            detector=self.name,
            timestamp=pkt.timestamp,
            severity_hint=3,
            title=f"Neuer Host im LAN: {ip} ({mac})",
            src=ip,
            details={"mac": mac, "frame": pkt.frame_number},
        )


# ---------------------------------------------------------------------------
# Detektor 2: DNS-Fehlerquote
# ---------------------------------------------------------------------------

class DnsFailureDetector(Detector):
    """Wiederholte ICMP-port-unreachable-Antworten pro (Ziel, Anfrager)-Paar.

    Szenario: Ein Gerät fragt einen DNS-Server, dort lauscht nichts auf
    Port 53 → ICMP Type 3 Code 3 zurück. Genau das war das Redmi-Problem."""

    name = "dns_failure_burst"
    WINDOW    = timedelta(seconds=60)
    THRESHOLD = 20

    def __init__(self) -> None:
        # (Antwortender-Host, Anfrager-Host) → deque[datetime]
        self._hits: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()

    def feed(self, pkt: Packet):
        if pkt.protocol not in ("icmp", "icmpv6"):
            return
        icmp = _icmp_layer(pkt)
        if str(icmp.get("icmp_icmp_type")) != "3":
            return
        if str(icmp.get("icmp_icmp_code")) != "3":
            return

        key = (pkt.src, pkt.dst)
        now = pkt.timestamp
        dq = self._hits[key]
        dq.append(now)

        cutoff = now - self.WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < self.THRESHOLD or key in self._alerted:
            return
        self._alerted.add(key)

        yield Event(
            detector=self.name,
            timestamp=now,
            severity_hint=6,
            title=f"DNS-Fehler: {pkt.dst} fragt {pkt.src} ({len(dq)}x/60s)",
            src=pkt.dst,
            dst=pkt.src,
            details={"count": len(dq), "window_s": 60},
        )


# ---------------------------------------------------------------------------
# Detektor 3: SYN-Fächer
# ---------------------------------------------------------------------------

class SynFanOutDetector(Detector):
    """Viele SYNs vom selben Sender an denselben Empfänger in kurzer Zeit.

    Zwei Ursachen möglich:
      a) Port-Scan (viele verschiedene Ziel-Ports) → severity 8
      b) Anwendung öffnet parallele HTTPS-Streams → severity 3
    """

    name = "syn_fan_out"
    WINDOW    = timedelta(seconds=10)
    THRESHOLD = 30

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._alerted: set[tuple[str, str]] = set()

    def feed(self, pkt: Packet):
        if pkt.protocol != "tcp" or pkt.dst_port is None:
            return
        flags = _tcp_flags(pkt)
        if "syn" not in flags or "ack" in flags:
            return

        key = (pkt.src, pkt.dst)
        now = pkt.timestamp
        dq = self._hits[key]
        dq.append((now, pkt.dst_port))

        cutoff = now - self.WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len(dq) < self.THRESHOLD or key in self._alerted:
            return
        self._alerted.add(key)

        distinct_ports = {p for _, p in dq}
        severity = 8 if len(distinct_ports) > 20 else 3

        yield Event(
            detector=self.name,
            timestamp=now,
            severity_hint=severity,
            title=(
                f"SYN-Fächer: {pkt.src} → {pkt.dst} "
                f"({len(dq)} SYNs, {len(distinct_ports)} Ports/10s)"
            ),
            src=pkt.src,
            dst=pkt.dst,
            details={
                "count": len(dq),
                "distinct_ports": len(distinct_ports),
                "sample_ports": sorted(distinct_ports)[:10],
            },
        )