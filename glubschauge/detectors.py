"""Regelbasierte Detektoren – die 'billige' Vorstufe zum LLM."""
from __future__ import annotations

import ipaddress
import logging
import statistics
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Iterable

from .events import Event, EventStore
from .models import Packet
from .oui import vendor_for

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Basisklasse
# ---------------------------------------------------------------------------

class Detector(ABC):
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
    """Extrahiert TCP-Flags aus dem tshark ek-JSON."""
    tcp = pkt.raw.get("tcp") or {}

    # 1. Boolesche Einzelfelder (tshark 4.x, zuverlässigste Quelle)
    bool_map = {
        "syn": "tcp_tcp_flags_syn",
        "ack": "tcp_tcp_flags_ack",
        "fin": "tcp_tcp_flags_fin",
        "rst": "tcp_tcp_flags_reset",
        "psh": "tcp_tcp_flags_push",
        "urg": "tcp_tcp_flags_urg",
    }
    found_bool = False
    flags: set[str] = set()
    for name, key in bool_map.items():
        v = tcp.get(key)
        if isinstance(v, bool):
            found_bool = True
            if v:
                flags.add(name)
    if found_bool:
        return flags

    # 2. Numerischer Wert
    raw = tcp.get("tcp_tcp_flags")
    if raw is not None:
        try:
            if isinstance(raw, str):
                s = raw.strip()
                v = int(s, 16) if s.lower().startswith("0x") else int(s)
            else:
                v = int(raw)
        except (TypeError, ValueError):
            v = None
        if v is not None:
            flags = set()
            if v & 0x01: flags.add("fin")
            if v & 0x02: flags.add("syn")
            if v & 0x04: flags.add("rst")
            if v & 0x08: flags.add("psh")
            if v & 0x10: flags.add("ack")
            if v & 0x20: flags.add("urg")
            return flags

    # 3. Wortform
    s = tcp.get("tcp_tcp_flags_str")
    if isinstance(s, str):
        sl = s.lower()
        if any(w in sl for w in ("syn", "ack", "fin", "rst", "psh", "urg")):
            return {
                p.strip().lower()
                for p in s.replace(",", "+").split("+")
                if p.strip()
            }

    return set()


def _has_tcp(pkt: Packet) -> bool:
    """True, wenn das Paket einen TCP-Layer hat – robust gegen
    tshark-Ketten wie 'eth:ethertype:ip:tcp:tcp.options'."""
    if "tcp" in pkt.protocols:
        return True
    return "tcp" in pkt.raw


def _has_icmp(pkt: Packet) -> bool:
    """True bei ICMP oder ICMPv6."""
    if "icmp" in pkt.protocols or "icmpv6" in pkt.protocols:
        return True
    return "icmp" in pkt.raw or "icmpv6" in pkt.raw


# ---------------------------------------------------------------------------
# Detektor 1: neuer Host im LAN
# ---------------------------------------------------------------------------

class NewHostDetector(Detector):
    """Erkennt neue physische Geräte (per MAC) im LAN.

    Hält zusätzlich die `last_seen`-Spalten in der DB aktuell, damit das
    Dashboard einen sinnvollen Online-/Idle-/Offline-Status zeigen kann.
    Die DB-Writes werden auf ein Intervall von TOUCH_INTERVAL_S gedrosselt,
    damit bei 1000+ pkts/s nicht die DB zum Flaschenhals wird.
    """

    name = "new_host"
    TOUCH_INTERVAL_S = 30.0   # pro MAC

    def __init__(self, store: EventStore, local_subnets: list[str],
                 trusted_macs: list[str] | None = None,
                 warmup_seconds: int = 60) -> None:
        self.store      = store
        self.subnets    = [ipaddress.ip_network(s) for s in local_subnets]
        self.trusted    = {m.lower() for m in (trusted_macs or [])}
        self.warmup_end = datetime.now(timezone.utc) + timedelta(seconds=warmup_seconds)

        # In-Memory-Caches, um DB-Queries pro Paket zu vermeiden
        self._known_ips:  set[tuple[str, str]] = store.load_hosts()
        self._known_macs: set[str]             = store.load_macs()
        self._last_mac_touch: dict[str, float] = {}

    def _is_local(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        return any(ip in net for net in self.subnets)

    @staticmethod
    def _is_usable_mac(m: str) -> bool:
        """Broadcast & Multicast-MACs rausfiltern."""
        if not m or m == "ff:ff:ff:ff:ff:ff":
            return False
        try:
            if int(m[:2], 16) & 0x01:      # multicast bit
                return False
        except (ValueError, IndexError):
            return False
        return True

    def feed(self, pkt: Packet):
        eth = pkt.raw.get("eth") or {}
        src_mac = (eth.get("eth_eth_src") or "").lower()
        dst_mac = (eth.get("eth_eth_dst") or "").lower()

        # (MAC, IP)-Paare sammeln, bei denen die IP lokal ist
        pairs: list[tuple[str, str]] = []
        if pkt.src and pkt.src != "?" and self._is_local(pkt.src) \
                and self._is_usable_mac(src_mac):
            pairs.append((src_mac, pkt.src))
        if pkt.dst and pkt.dst != "?" and self._is_local(pkt.dst) \
                and self._is_usable_mac(dst_mac):
            pairs.append((dst_mac, pkt.dst))

        if not pairs:
            return

        now    = pkt.timestamp
        now_ts = now.timestamp()
        warmup = now < self.warmup_end

        for mac, ip in pairs:
                    is_new_mac  = mac not in self._known_macs
                    is_new_pair = (mac, ip) not in self._known_ips

                    # --- Neue Geräte persistieren + Event erzeugen ---
                    if is_new_mac or is_new_pair:
                        vendor = vendor_for(mac)

                        if is_new_mac:
                            self.store.upsert_mac(mac, vendor, now)
                            self._known_macs.add(mac)
                        if is_new_pair:
                            self.store.remember_host(mac, ip, now)
                            self._known_ips.add((mac, ip))

                        # Nur alarmieren, wenn NICHT vertrauenswürdig und Warmup vorbei
                        if not warmup and is_new_mac and (mac not in self.trusted):
                            yield Event(
                                detector=self.name,
                                timestamp=now,
                                severity_hint=3,
                                title=f"Neues Gerät: {vendor} ({mac}) — {ip}",
                                src=ip,
                                dst="",
                                details={"mac": mac, "ip": ip, "vendor": vendor},
                            )

                    # --- last_seen pflegen (gedrosselt, AUCH FÜR TRUSTED HOSTS) ---
                    last = self._last_mac_touch.get(mac, 0.0)
                    if (now_ts - last) > self.TOUCH_INTERVAL_S:
                        self.store.touch_mac(mac, now)
                        self._last_mac_touch[mac] = now_ts


# ---------------------------------------------------------------------------
# Detektor 2a: offene Dienste / Serverantworten
# ---------------------------------------------------------------------------

WELL_KNOWN_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP Server", 68: "DHCP Client", 80: "HTTP (Web)", 123: "NTP",
    137: "NetBIOS", 139: "NetBIOS", 443: "HTTPS (Web/TLS)", 445: "SMB / Windows Share",
    548: "AFP (Apple)", 631: "IPP (Drucker)", 1900: "SSDP / UPnP",
    3000: "Grafana / Dev-Web", 3389: "RDP (Remote Desktop)",
    5000: "Synology / UPnP", 5353: "mDNS / Bonjour", 8006: "Proxmox VE",
    8080: "HTTP-Proxy / Alt", 8123: "Home Assistant", 8443: "HTTPS-Alt",
    9000: "Portainer", 9090: "Prometheus / Cockpit", 9100: "Node Exporter"
}

class ServiceDiscoveryDetector(Detector):
    """Erkennt passiv offene Ports und lauschende Dienste anhand von Server-Antworten."""
    name = "service_discovery"

    def __init__(self, store: EventStore, local_subnets: list[str]) -> None:
        self.store = store
        self.subnets = [ipaddress.ip_network(s) for s in local_subnets]
        self._seen_cache: set[tuple[str, int, str]] = set()

    def _is_local(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (ip.is_loopback or ip.is_multicast) and any(ip in net for net in self.subnets)
        except ValueError:
            return False

    def feed(self, pkt: Packet):
        # Nur Pakete betrachten, die von einem lokalen Host gesendet werden
        if not pkt.src or not self._is_local(pkt.src) or pkt.src_port is None:
            return

        eth = pkt.raw.get("eth") or {}
        src_mac = (eth.get("eth_eth_src") or "").lower()
        if not src_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return

        port = pkt.src_port
        proto = "tcp" if _has_tcp(pkt) else ("udp" if "udp" in pkt.protocols or "udp" in pkt.raw else None)
        if not proto:
            return

        is_open_service = False
        if proto == "tcp":
            flags = _tcp_flags(pkt)
            # SYN+ACK = Server hat eine Verbindung auf diesem Port akzeptiert!
            if "syn" in flags and "ack" in flags:
                is_open_service = True
        elif proto == "udp":
            # Bekannter UDP-Serviceport, von dem aus gesendet wird
            if port in (53, 67, 123, 1900, 5353):
                is_open_service = True

        if is_open_service:
            service_name = WELL_KNOWN_SERVICES.get(port, pkt.protocol.upper() if pkt.protocol not in ("tcp", "udp") else "")
            cache_key = (src_mac, port, proto)
            if cache_key not in self._seen_cache:
                self._seen_cache.add(cache_key)
                self.store.upsert_port(src_mac, pkt.src, port, proto, service_name, pkt.timestamp)
                log.info("Offener Dienst erkannt: %s (%s) Port %d/%s [%s]", pkt.src, src_mac, port, proto, service_name)


# ---------------------------------------------------------------------------
# Detektor 2b: DNS-Fehlerquote
# ---------------------------------------------------------------------------

class DnsFailureDetector(Detector):
    """Erkennt Bursts von DNS-Fehlern (ICMP port unreachable).

    Cooldown statt permanentem `_alerted`-Set: nach Ablauf des Cooldowns
    meldet derselbe (src, dst)-Pfad erneut, wenn er immer noch fehlerhaft ist.
    """

    name = "dns_failure_burst"

    def __init__(
        self,
        threshold: int = 20,
        window_s:  int = 60,
        cooldown_s: int = 300,
    ) -> None:
        self.threshold = threshold
        self.window    = timedelta(seconds=window_s)
        self.cooldown  = timedelta(seconds=cooldown_s)
        self._hits: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}

    def feed(self, pkt: Packet):
        if not _has_icmp(pkt):
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
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < self.threshold:
            return

        last = self._last_alert.get(key)
        if last is not None and (now - last) < self.cooldown:
            return

        self._last_alert[key] = now

        yield Event(
            detector=self.name, timestamp=now, severity_hint=6,
            title=f"DNS-Fehler: {pkt.dst} fragt {pkt.src} ({len(dq)}x/"
                  f"{int(self.window.total_seconds())}s)",
            src=pkt.dst, dst=pkt.src,
            details={
                "count": len(dq),
                "window_s": int(self.window.total_seconds()),
                "cooldown_s": int(self.cooldown.total_seconds()),
            },
        )


# ---------------------------------------------------------------------------
# Detektor 3: SYN-Fächer
# ---------------------------------------------------------------------------

class SynFanOutDetector(Detector):
    """Erkennt SYN-Fächer (Port-Scans, Verbindungsversuche an viele Ports).

    Cooldown statt permanentem `_alerted`-Set: nach Ablauf des Cooldowns
    meldet derselbe (src, dst)-Pfad erneut, wenn er immer noch aktiv ist.
    """

    name = "syn_fan_out"

    def __init__(
        self,
        threshold: int = 15,
        window_s:  int = 10,
        cooldown_s: int = 300,
        debug_first_n: int = 0,
    ) -> None:
        self.threshold = threshold
        self.window    = timedelta(seconds=window_s)
        self.cooldown  = timedelta(seconds=cooldown_s)
        self._hits: dict[tuple[str, str], deque[tuple[datetime, int]]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}
        self._debug_left = debug_first_n

    def feed(self, pkt: Packet):
        if not _has_tcp(pkt) or pkt.dst_port is None:
            return

        flags = _tcp_flags(pkt)

        if self._debug_left > 0:
            tcp = pkt.raw.get("tcp") or {}
            log.info("TCP-DEBUG pkt#%d %s:%s → %s:%s flags=%s",
                     pkt.frame_number, pkt.src, pkt.src_port,
                     pkt.dst, pkt.dst_port, sorted(flags))
            log.info("TCP-DEBUG keys=%s", sorted(tcp.keys()))
            log.info("TCP-DEBUG full=%r", tcp)
            self._debug_left -= 1

        if "syn" not in flags or "ack" in flags:
            return

        key = (pkt.src, pkt.dst)
        now = pkt.timestamp
        dq  = self._hits[key]
        dq.append((now, pkt.dst_port))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len(dq) < self.threshold:
            return

        last = self._last_alert.get(key)
        if last is not None and (now - last) < self.cooldown:
            return

        self._last_alert[key] = now

        distinct_ports = {p for _, p in dq}
        severity = 8 if len(distinct_ports) > 20 else 3

        yield Event(
            detector=self.name, timestamp=now, severity_hint=severity,
            title=(f"SYN-Fächer: {pkt.src} → {pkt.dst} "
                   f"({len(dq)} SYNs, {len(distinct_ports)} Ports/"
                   f"{int(self.window.total_seconds())}s)"),
            src=pkt.src, dst=pkt.dst,
            details={
                "count": len(dq),
                "distinct_ports": len(distinct_ports),
                "sample_ports": sorted(distinct_ports)[:10],
                "cooldown_s": int(self.cooldown.total_seconds()),
            },
        )


# ---------------------------------------------------------------------------
# Detektor 4: Beaconing
# ---------------------------------------------------------------------------

class BeaconingDetector(Detector):
    name = "beaconing"

    def __init__(self, min_samples: int = 5, max_jitter_cv: float = 0.15,
                 min_interval_s: int = 5, max_interval_s: int = 600,
                 window_minutes: int = 30, cooldown_minutes: int = 60) -> None:
        self.min_samples    = min_samples
        self.max_jitter_cv  = max_jitter_cv
        self.min_interval_s = min_interval_s
        self.max_interval_s = max_interval_s
        self.window         = timedelta(minutes=window_minutes)
        self.cooldown       = timedelta(minutes=cooldown_minutes)
        self._hits: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], datetime] = {}

    def feed(self, pkt: Packet):
        if not _has_tcp(pkt) or pkt.dst_port is None:
            return
        flags = _tcp_flags(pkt)
        if "syn" not in flags or "ack" in flags:
            return
        if pkt.dst_port not in (443, 80, 8443, 8080, 53, 123):
            return

        key = (pkt.src, pkt.dst)
        now = pkt.timestamp
        dq = self._hits[key]
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

        if len(dq) < self.min_samples:
            return

        last = self._last_alert.get(key)
        if last is not None and (now - last) < self.cooldown:
            return

        intervals = [(dq[i] - dq[i-1]).total_seconds() for i in range(1, len(dq))]
        intervals = [i for i in intervals
                     if self.min_interval_s <= i <= self.max_interval_s]
        if len(intervals) < self.min_samples - 1:
            return

        mean_i = statistics.mean(intervals)
        stdev_i = statistics.pstdev(intervals)
        cv = stdev_i / mean_i if mean_i > 0 else 999

        if cv > self.max_jitter_cv:
            return

        self._last_alert[key] = now

        yield Event(
            detector=self.name, timestamp=now, severity_hint=7,
            title=(f"Beaconing: {pkt.src} → {pkt.dst}:{pkt.dst_port} "
                   f"({len(intervals)} Intervalle, Ø {mean_i:.1f} s, CV {cv:.2f})"),
            src=pkt.src, dst=pkt.dst,
            details={"samples": len(dq), "mean_interval_s": round(mean_i, 2),
                     "stdev_interval_s": round(stdev_i, 2), "cv": round(cv, 3),
                     "dst_port": pkt.dst_port,
                     "intervals_sample_s": [round(i, 1) for i in intervals[:6]]},
        )


# ---------------------------------------------------------------------------
# Detektor 5: High-Volume Flow
# ---------------------------------------------------------------------------

class HighVolumeFlowDetector(Detector):
    name = "high_volume"

    def __init__(self, threshold_mb: float = 100.0, window_s: int = 60,
                 cooldown_minutes: int = 10) -> None:
        self.threshold_bytes = int(threshold_mb * 1024 * 1024)
        self.window          = timedelta(seconds=window_s)
        self.cooldown        = timedelta(minutes=cooldown_minutes)
        self._hits: dict[tuple, deque[tuple[datetime, int]]] = defaultdict(deque)
        self._last_alert: dict[tuple, datetime] = {}

    def _flow_key(self, pkt: Packet) -> tuple | None:
        if pkt.dst_port is None:
            return None
        # src_port NICHT im Key: sonst wird jede neue TCP-Verbindung
        # (neuer ephemerer Quellport) zu einem neuen Flow und derselbe
        # Transfer feuert dutzende Male.
        # Protokoll NICHT im Key: tshark klassifiziert dieselbe Verbindung
        # je nach Dekodierungstiefe als "tcp" oder "tls".
        return (pkt.src, pkt.dst, pkt.dst_port)

    def feed(self, pkt: Packet):
        if not any(p in pkt.protocols for p in ("tcp", "tls", "http", "https", "quic")):
            if "tcp" not in pkt.raw:
                return
        key = self._flow_key(pkt)
        if key is None:
            return
        now = pkt.timestamp
        dq = self._hits[key]
        dq.append((now, pkt.length))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        total = sum(b for _, b in dq)
        if total < self.threshold_bytes:
            return
        last = self._last_alert.get(key)
        if last is not None and (now - last) < self.cooldown:
            return
        self._last_alert[key] = now
        mb = total / (1024 * 1024)
        yield Event(
            detector=self.name, timestamp=now, severity_hint=3,
            title=(f"Hohe Datenrate: {pkt.src} → {pkt.dst}:{pkt.dst_port} "
                   f"({mb:.1f} MB in {int(self.window.total_seconds())} s)"),
            src=pkt.src, dst=pkt.dst,
            details={"bytes": total, "mb": round(mb, 1),
                     "window_s": int(self.window.total_seconds()),
                     "src_port": pkt.src_port, "dst_port": pkt.dst_port,
                     "protocol": pkt.protocol},
        )


# ---------------------------------------------------------------------------
# Detektor 6: Multi-Target SYN-Scan (LAN)
# ---------------------------------------------------------------------------

class SynFanOutMultiDetector(Detector):
    """Erkennt Multi-Target-Scans: eine Quelle kontaktiert innerhalb eines
    kurzen Fensters mehrere verschiedene LAN-Ziele auf vielen verschiedenen
    Ports mit SYN-Paketen.

    Beispiel aus dem echten Netz:
        192.168.0.194 → .1, .2, .214, .245
        auf je 16–25 Ports, alles innerhalb von 3 Sekunden.
    Das ist die Signatur eines LAN-Scans oder lateraler Bewegung.

    Abgrenzung zu `SynFanOutDetector`: der klassische Detektor feuert
    PRO (src, dst)-Paar. Wenn ein Host aber vier LAN-Ziele in drei
    Sekunden scannt, ist der Zusammenhang wichtig – und den sieht nur
    dieser Detektor.

    Es werden nur Ziele in `local_subnets` gezählt. Scans auf externe
    IPs (z. B. viele Ports zu einem Microsoft-Server) sind oft legitim
    und werden hier ignoriert.
    """
    name = "syn_fan_out_multi"

    def __init__(
        self,
        window_s: int = 10,
        min_targets: int = 3,
        min_distinct_ports: int = 20,
        cooldown_s: int = 300,
        local_subnets: list[str] | None = None,
    ) -> None:
        self.window              = timedelta(seconds=window_s)
        self.cooldown            = timedelta(seconds=cooldown_s)
        self.min_targets         = min_targets
        self.min_distinct_ports  = min_distinct_ports
        self.subnets             = [ipaddress.ip_network(s) for s in (local_subnets or [])]
        # pro Quelle: deque von (ts, dst_ip, dst_port)
        self._hits: dict[str, deque[tuple[datetime, str, int]]] = defaultdict(deque)
        self._last_alert: dict[str, datetime] = {}

    def _is_local(self, ip_str: str) -> bool:
        if not self.subnets:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            return False
        return any(ip in net for net in self.subnets)

    def feed(self, pkt: Packet):
        if not _has_tcp(pkt) or pkt.dst_port is None:
            return
        flags = _tcp_flags(pkt)
        if "syn" not in flags or "ack" in flags:
            return
        if not self._is_local(pkt.dst):
            return

        now = pkt.timestamp
        src = pkt.src
        dq  = self._hits[src]
        dq.append((now, pkt.dst, pkt.dst_port))
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        distinct_targets = {t for _, t, _ in dq}
        distinct_ports   = {p for _, _, p in dq}

        if len(distinct_targets) < self.min_targets:
            return
        if len(distinct_ports) < self.min_distinct_ports:
            return

        last = self._last_alert.get(src)
        if last is not None and (now - last) < self.cooldown:
            return
        self._last_alert[src] = now

        # Severity-Eskalation: mehr Ziele / mehr Ports → härter
        if len(distinct_targets) >= 5 or len(distinct_ports) >= 100:
            severity = 8
        else:
            severity = 7

        targets_sorted = sorted(distinct_targets)
        dst_str = (
            ", ".join(targets_sorted)
            if len(targets_sorted) <= 3
            else f"{len(targets_sorted)} Ziele"
        )

        yield Event(
            detector=self.name,
            timestamp=now,
            severity_hint=severity,
            title=(f"LAN-Scan: {src} hat {len(distinct_targets)} LAN-Ziele "
                   f"auf {len(distinct_ports)} Ports in "
                   f"{int(self.window.total_seconds())}s kontaktiert"),
            src=src,
            dst=dst_str,
            details={
                "targets":          targets_sorted,
                "distinct_targets": len(distinct_targets),
                "distinct_ports":   len(distinct_ports),
                "total_syns":       len(dq),
                "sample_ports":     sorted(distinct_ports)[:15],
                "window_s":         int(self.window.total_seconds()),
                "cooldown_s":       int(self.cooldown.total_seconds()),
            },
        )


# ---------------------------------------------------------------------------
# Detektor 7: ARP-Spoofing
# ---------------------------------------------------------------------------

class ArpSpoofDetector(Detector):
    name = "arp_spoof"

    def __init__(self, target_ip: str, target_mac: str) -> None:
        self.target_ip  = target_ip
        self.target_mac = target_mac.lower()
        self._cache: dict[str, str] = {target_ip: self.target_mac}

    def feed(self, pkt: Packet):
        if "arp" not in pkt.protocols:
            return

        arp = pkt.raw.get("arp", {})
        # Wir verwenden die exakten Namen aus dem tshark-Trace
        sender_ip  = arp.get("arp_arp_src_proto_ipv4")
        sender_mac = (arp.get("arp_arp_src_hw_mac") or "").lower()

        if not sender_ip or not sender_mac:
            return

        # Check: Ist die IP bekannt und hat sich die MAC geändert?
        if sender_ip in self._cache and self._cache[sender_ip] != sender_mac:
            old_mac = self._cache[sender_ip]

            # Alarm schlagen, wenn unser Zielgerät (Router) plötzlich eine andere MAC hat
            if sender_ip == self.target_ip:
                yield Event(
                    detector=self.name,
                    timestamp=pkt.timestamp,
                    severity_hint=9,
                    title=f"ARP-SPOOFING: {sender_ip} ist nun {sender_mac} (war: {old_mac})",
                    src=sender_mac,
                    dst=sender_ip,
                    details={"ip": sender_ip, "new_mac": sender_mac, "old_mac": old_mac},
                )

        # Cache mit der aktuell gesehenen MAC für diese IP aktualisieren
        self._cache[sender_ip] = sender_mac