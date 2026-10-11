"""Prompt-Bau und Modell-Router."""
from __future__ import annotations

import json

from .events import Event

SYSTEM_PROMPT = """Du bist ein präziser Netzwerk-Analyst für ein Heimnetzwerk mit 5–15 Geräten
(Router, PCs, iPhones, Raspberry Pi, Smart-TV).

Antworte AUSSCHLIESSLICH mit gültigem JSON. Kein Text drumherum.

Severity-Skala – halte dich strikt daran:
  0  völlig erwartetes Hintergrundrauschen (ARP, NTP, mDNS, SSDP, IGMP)
  2  neue Geräte im eigenen LAN, Erstverbindung (discovery)
  3  beobachtenswert, aber unklar
  5  wiederholte Fehler, ungewöhnliche Ports
  7  verdächtig: Scan-Muster, unbekannte Protokolle
  9  kritisch: Klartext-Credentials, C2-Beaconing

Wichtige Regeln:
- Ein neuer Host im eigenen LAN ist NORMAL. Severity 2, discovery.
- Kategorie MUSS eine von diesen sein: dns, connectivity, security, performance, discovery, unknown.
- explanation: maximal 2 kurze deutsche Sätze.
- IPv6-Adressen mit Präfix fe80:: sind Link-Local und völlig normal,
  ebenso 2a02::/16 als globales Präfix. Sie sind NICHT fehlerhaft.

Beispiele:
  Event: "Neuer Host im LAN: 192.168.0.50 (aa:bb:cc:dd:ee:ff)"
  Antwort: {"severity": 2, "category": "discovery", "explanation": "Neues Gerät im lokalen Netzwerk, üblicher Vorgang."}

  Event: "DNS-Fehler: 192.168.0.5 fragt 192.168.0.10 (47x/60s)"
  Antwort: {"severity": 6, "category": "dns", "explanation": "Wiederholte DNS-Anfragen an einen nicht antwortenden Server."}
"""


PROMPT_TEMPLATE = """Bewerte folgendes Ereignis:

Detektor:   {detector}
Zeitpunkt:  {timestamp}
Quelle:     {src}
Ziel:       {dst}
Regel-Hinweis: {severity_hint}/10
Titel:      {title}
Details:
{details_json}

Antworte mit JSON:
{{"severity": <0-10>, "category": "<dns|connectivity|security|performance|discovery|unknown>", "explanation": "<max 2 Sätze>"}}"""


def build_prompt(ev: Event) -> str:
    details = json.dumps(ev.details, indent=2, ensure_ascii=False, default=str)
    return PROMPT_TEMPLATE.format(
        detector=ev.detector,
        timestamp=ev.timestamp.isoformat(),
        src=ev.src or "—",
        dst=ev.dst or "—",
        severity_hint=ev.severity_hint,
        title=ev.title,
        details_json=details,
    )


MODEL_ROUTER = {
    "filter":   "llama3.2:3b",              # 8B-Instruct-Modell: zuverlässig, ~500 ms
    "analyze":  "llama3.1:8b",
    "forensic": "qwen2.5-coder:14b",
}


def model_for(stage: str) -> str:
    return MODEL_ROUTER.get(stage, MODEL_ROUTER["analyze"])