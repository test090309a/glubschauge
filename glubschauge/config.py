"""Konfiguration aus config.toml laden."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
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
    # new_host
    new_host_warmup_seconds: int = 60
    # syn_fan_out
    syn_fan_out_threshold:   int = 15
    syn_fan_out_window_s:    int = 10
    syn_fan_out_cooldown_s:  int = 300
    # syn_fan_out_multi
    syn_fan_out_multi_window_s:           int = 10
    syn_fan_out_multi_min_targets:        int = 3
    syn_fan_out_multi_min_distinct_ports: int = 20
    syn_fan_out_multi_cooldown_s:         int = 300
    # dns_failure_burst
    dns_failure_threshold:   int = 20
    dns_failure_window_s:    int = 60
    dns_failure_cooldown_s:  int = 300
    # beaconing
    beaconing_min_samples:    int   = 5
    beaconing_max_jitter_cv:  float = 0.15
    beaconing_window_minutes: int   = 30
    # high_volume
    volume_threshold_mb: float = 100.0
    volume_window_s:     int   = 60


@dataclass(slots=True)
class RingConfig:
    enabled:         bool = True
    ring_dir:        str  = "ring"
    file_interval_s: int  = 10
    num_files:       int  = 12
    bpf_filter:      str  = ""


@dataclass(slots=True)
class LlmConfig:
    """Entscheider + Erklärer-Pipeline (Tev1 + Chat-Modell)."""
    decision_mode:          bool  = True
    decision_model:         str   = "tev1:4b"
    explanation_model:      str   = "llama3.2:3b"
    # Schwellen für die Severity-Regel
    scan_threshold:         float = 0.75
    beaconing_threshold:    float = 0.70
    internal_threshold:     float = 0.30
    external_threshold:     float = 0.70
    internal_beaconing_cap: int   = 3
    # Warmup beim Start (Tev1 einmal vorladen, ~20 s)
    warmup_on_start:        bool  = True


@dataclass(slots=True)
class Config:
    capture:   CaptureConfig
    network:   NetworkConfig
    detectors: DetectorConfig
    ring:      RingConfig
    llm:       LlmConfig


def load(path: str | Path = "config.toml") -> Config:
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    cap      = raw.get("capture",   {})
    net      = raw.get("network",   {})
    det      = raw.get("detectors", {})
    ring_raw = raw.get("ring",      {})
    llm_raw  = raw.get("llm",       {})

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
            new_host_warmup_seconds = int(det.get("new_host_warmup_seconds", 60)),

            syn_fan_out_threshold   = int(det.get("syn_fan_out_threshold", 15)),
            syn_fan_out_window_s    = int(det.get("syn_fan_out_window_s", 10)),
            syn_fan_out_cooldown_s  = int(det.get("syn_fan_out_cooldown_s", 300)),

            syn_fan_out_multi_window_s           = int(det.get("syn_fan_out_multi_window_s", 10)),
            syn_fan_out_multi_min_targets        = int(det.get("syn_fan_out_multi_min_targets", 3)),
            syn_fan_out_multi_min_distinct_ports = int(det.get("syn_fan_out_multi_min_distinct_ports", 20)),
            syn_fan_out_multi_cooldown_s         = int(det.get("syn_fan_out_multi_cooldown_s", 300)),

            dns_failure_threshold   = int(det.get("dns_failure_threshold", 20)),
            dns_failure_window_s    = int(det.get("dns_failure_window_s", 60)),
            dns_failure_cooldown_s  = int(det.get("dns_failure_cooldown_s", 300)),

            beaconing_min_samples    = int(det.get("beaconing_min_samples", 5)),
            beaconing_max_jitter_cv  = float(det.get("beaconing_max_jitter_cv", 0.15)),
            beaconing_window_minutes = int(det.get("beaconing_window_minutes", 30)),

            volume_threshold_mb      = float(det.get("volume_threshold_mb", 100.0)),
            volume_window_s          = int(det.get("volume_window_s", 60)),
        ),
        ring=RingConfig(
            enabled         = bool(ring_raw.get("enabled", True)),
            ring_dir        = ring_raw.get("ring_dir", "ring"),
            file_interval_s = int(ring_raw.get("file_interval_s", 10)),
            num_files       = int(ring_raw.get("num_files", 12)),
            bpf_filter      = ring_raw.get("bpf_filter", ""),
        ),
        llm=LlmConfig(
            decision_mode          = bool(llm_raw.get("decision_mode", True)),
            decision_model         = llm_raw.get("decision_model", "tev1:4b"),
            explanation_model      = llm_raw.get("explanation_model", "llama3.2:3b"),
            scan_threshold         = float(llm_raw.get("scan_threshold", 0.75)),
            beaconing_threshold    = float(llm_raw.get("beaconing_threshold", 0.70)),
            internal_threshold     = float(llm_raw.get("internal_threshold", 0.30)),
            external_threshold     = float(llm_raw.get("external_threshold", 0.70)),
            internal_beaconing_cap = int(llm_raw.get("internal_beaconing_cap", 3)),
            warmup_on_start        = bool(llm_raw.get("warmup_on_start", True)),
        ),
    )