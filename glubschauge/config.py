"""Konfiguration aus config.toml laden."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class CaptureConfig:
    tshark_path: str
    interface:   str
    bpf_filter:  str


@dataclass(slots=True)
class NetworkConfig:
    local_subnets: list[str]
    trusted_hosts: list[str]


@dataclass(slots=True)
class DetectorConfig:
    new_host_warmup_seconds: int = 60


@dataclass(slots=True)
class RingConfig:
    enabled:         bool = True
    ring_dir:        str  = "ring"
    file_interval_s: int  = 10
    num_files:       int  = 12
    bpf_filter:      str  = ""


@dataclass(slots=True)
class Config:
    capture:   CaptureConfig
    network:   NetworkConfig
    detectors: DetectorConfig
    ring:      RingConfig


def load(path: str | Path = "config.toml") -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    cap      = raw.get("capture",   {})
    net      = raw.get("network",   {})
    det      = raw.get("detectors", {})
    ring_raw = raw.get("ring",      {})

    return Config(
        capture=CaptureConfig(
            tshark_path=cap.get("tshark_path", r"M:\Wireshark\tshark.exe"),
            interface=cap.get("interface", "8"),
            bpf_filter=cap.get("bpf_filter", "not port 22"),
        ),
        network=NetworkConfig(
            local_subnets=net.get("local_subnets", ["192.168.0.0/24"]),
            trusted_hosts=[m.lower() for m in net.get("trusted_hosts", [])],
        ),
        detectors=DetectorConfig(
            new_host_warmup_seconds=int(det.get("new_host_warmup_seconds", 60)),
        ),
        ring=RingConfig(
            enabled=bool(ring_raw.get("enabled", True)),
            ring_dir=ring_raw.get("ring_dir", "ring"),
            file_interval_s=int(ring_raw.get("file_interval_s", 10)),
            num_files=int(ring_raw.get("num_files", 12)),
            bpf_filter=ring_raw.get("bpf_filter", ""),
        ),
    )