"""Prompt-Bau, State-Builder und Severity-Regel für die LLM-Pipeline.

Zwei Pfade:
  * Legacy-Pfad:  build_prompt() + SYSTEM_PROMPT → /api/generate (llama3.2:3b)
  * Decision-Pfad: build_decision() + final_severity() → /v1/systemone (tev1)

Der Decision-Pfad ist der neue Standard. Der Legacy-Pfad bleibt für
Rollback und für die manuelle Re-Analyse (TUI, Taste `R`) erhalten.
"""
from __future__ import annotations

import ipaddress
import json

from .events import Event


# ---------------------------------------------------------------------------
# Legacy-Prompt (unverändert, für Re-Analyse und Rollback)
# ---------------------------------------------------------------------------

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

Regeln für Scan-Erkennung:
- Ein "syn_fan_out"-Event ist NIE Severity unter 6.
- Ein "syn_fan_out_multi"-Event ist IMMER Severity 7–9, Kategorie security.
- "Verdächtig, aber ohne klaren Hinweis" ist KEINE gültige Erklärung für Port-Scans.
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
    "filter":   "llama3.2:3b",
    "analyze":  "llama3.1:8b",
    "forensic": "qwen2.5-coder:14b",
}


def model_for(stage: str) -> str:
    return MODEL_ROUTER.get(stage, MODEL_ROUTER["analyze"])


# ---------------------------------------------------------------------------
# Decision-Pfad (Tev1)
# ---------------------------------------------------------------------------

def _target_scope(ip_str: str, local_subnets: list[str]) -> str:
    """Klassifiziert eine IP für den State.

    Rückgabe: own_lan | external_internet | private_other |
              loopback | none | unknown
    """
    if not ip_str or ip_str in ("—", "?"):
        return "none"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    for s in local_subnets:
        try:
            if ip in ipaddress.ip_network(s):
                return "own_lan"
        except ValueError:
            continue
    if ip.is_private:
        return "private_other"
    return "external_internet"


def build_state(ev: Event, local_subnets: list[str]) -> str:
    """Kompakter, englischer State mit explizitem Scope-Tag für src/dst."""
    scope_src = _target_scope(ev.src, local_subnets)
    scope_dst = _target_scope(ev.dst, local_subnets)
    details = json.dumps(ev.details, ensure_ascii=False, default=str)
    return (
        f"detector={ev.detector}\n"
        f"title={ev.title}\n"
        f"src={ev.src or '—'}  [scope={scope_src}]\n"
        f"dst={ev.dst or '—'}  [scope={scope_dst}]\n"
        f"rule_hint={ev.severity_hint}/10\n"
        f"details={details}"
    )


def build_questions() -> dict:
    """Fragenkatalog für /v1/systemone. Einmalig bauen, wiederverwenden."""
    return {
        "severity": {
            "type": "score",
            "instructions": (
                "How severe is this network event for a small home network "
                "with 5-15 devices and one router?"
            ),
            "criteria": [
                "harmless background noise",
                "normal, uninteresting",
                "informational",
                "minor, worth noting",
                "notable",
                "concerning",
                "suspicious",
                "likely malicious activity",
                "clear attack",
                "critical security incident",
                "emergency",
            ],
        },
        "category": {
            "type": "choice",
            "instructions": "Which category best matches this event?",
            "criteria": {
                "dns":          "DNS resolution or lookup problem",
                "connectivity": "Network reachability or connection issue",
                "security":     "Attack, scan, lateral movement, policy violation",
                "performance":  "Bandwidth, latency, or throughput issue",
                "discovery":    "New device or normal network discovery",
                "unknown":      "None of the above fits.",
            },
        },
        "is_scan": {
            "type": "noul",
            "instructions": "Is this a port scan or network scan?",
        },
        "is_beaconing": {
            "type": "noul",
            "instructions": (
                "Does this look like periodic command-and-control beaconing?"
            ),
        },
        "is_external_destination": {
            "type": "noul",
            "instructions": (
                "Does this event involve traffic to a destination OUTSIDE "
                "the home network (a public internet server, not a device "
                "in the user's own LAN)?"
            ),
        },
    }


def build_decision(ev: Event, local_subnets: list[str],
                   questions: dict | None = None) -> tuple[str, dict]:
    """Liefert (state, questions) für den Tev1-Call."""
    return build_state(ev, local_subnets), (questions or build_questions())


# ---------------------------------------------------------------------------
# Severity-Regel — die zentrale Logik
# ---------------------------------------------------------------------------

def _noul(answers: dict, key: str) -> float | None:
    v = (answers.get(key) or {}).get("noul")
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def final_severity(
    rule_hint: int,
    answers: dict,
    scan_threshold:         float = 0.75,
    beaconing_threshold:    float = 0.70,
    internal_threshold:     float = 0.30,
    external_threshold:     float = 0.70,
    internal_beaconing_cap: int   = 3,
) -> int:
    """Berechnet die finale Severity aus Regel-Hint + Tev1-Signalen.

    Priorität:
      1. Port-Scan ist immer ernst — unabhängig vom Ziel.
      2. Externes Beaconing → C2-Verdacht → hochstufen.
      3. Internes Beaconing → NTP/DNS/Backup → runterstufen.
      4. Sonst: Regel-Hint unverändert.
    """
    if not answers:
        return rule_hint

    is_scan      = _noul(answers, "is_scan")
    is_beaconing = _noul(answers, "is_beaconing")
    is_external  = _noul(answers, "is_external_destination")

    # 1. Port-Scan
    if is_scan is not None and is_scan > scan_threshold:
        return max(rule_hint, 7)

    # 2./3. Beaconing
    if is_beaconing is not None and is_beaconing > beaconing_threshold:
        if is_external is not None and is_external > external_threshold:
            return max(rule_hint, 7)          # externes C2
        if is_external is not None and is_external < internal_threshold:
            return min(rule_hint, internal_beaconing_cap)  # NTP/DNS/Backup
        return rule_hint                       # unklar → hint behalten

    return rule_hint


# ---------------------------------------------------------------------------
# Erklärungs-Prompt (llama3.2:3b, nur Prosa, keine Bewertung)
# ---------------------------------------------------------------------------

EXPLANATION_SYSTEM = (
    "Du bist ein sachlicher Netzwerk-Analyst für ein Heimnetzwerk. "
    "Du bekommst ein Ereignis und eine fertige Bewertung (Severity und "
    "Kategorie). Schreibe 1–2 kurze deutsche Sätze, die einem Heimnetz-"
    "Nutzer erklären, was hier passiert. Ändere die Bewertung NICHT. "
    "Wiederhole keine Zahlen, kein Vorwort, kein JSON."
)


EXPLANATION_TEMPLATE = """Ereignis:
Detektor:  {detector}
Titel:     {title}
Quelle:    {src}
Ziel:      {dst}
Details:   {details_json}

Fertige Bewertung:
Severity:  {severity}/10
Kategorie: {category}

Erklärung (1–2 Sätze, deutsch):"""


def build_explanation_prompt(ev: Event, severity: int, category: str) -> str:
    details = json.dumps(ev.details, ensure_ascii=False, default=str)
    return EXPLANATION_TEMPLATE.format(
        detector=ev.detector,
        title=ev.title,
        src=ev.src or "—",
        dst=ev.dst or "—",
        details_json=details,
        severity=severity,
        category=category,
    )