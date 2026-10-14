"""test_decision.py — Experiment: tev1:4b als Entscheider statt Chat-LLM.

V3: State wird mit Ziel-Scope-Tags angereichert (own_lan / external_internet
/ private_other / loopback). Zusätzliche Noul-Frage is_external_destination.
Damit soll Tev1 interne periodische Muster (NTP/DNS/Backup an Router/NAS)
von externem C2-Beaconing unterscheiden.

Benutzung:
    python test_decision.py                    # Positiv-Events
    python test_decision.py --neg              # Negativ-Events
    python test_decision.py --all              # beide
    python test_decision.py --all --raw        # mit voller JSON-Antwort
    python test_decision.py --compare          # zusätzlich Chat-Pfad
    python test_decision.py --only "NTP"       # Substring-Filter

Voraussetzung:
    ollama --version          # >= 0.35 nötig
    ollama pull tev1:4b
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
import time
from typing import Any

try:
    import httpx  # type: ignore[reportMissingImports]
except ModuleNotFoundError:  # pragma: no cover - optional dependency at runtime
    httpx = None  # type: ignore[assignment]

OLLAMA         = "http://localhost:11434"
DECISION_MODEL = "tev1:4b"
CHAT_MODEL     = "llama3.2:3b"

# Muss zur config.toml passen (network.local_subnets)
LOCAL_SUBNETS = [
    "192.168.0.0/24",
    "fe80::/10",
    "ff02::/16",
    "224.0.0.0/4",
]


# ---------------------------------------------------------------------------
# Scope-Klassifikation
# ---------------------------------------------------------------------------

def _target_scope(ip_str: str, local_subnets: list[str] = LOCAL_SUBNETS) -> str:
    """Klassifiziert eine IP-Adresse für Tev1.

    Rückgabe: own_lan | external_internet | private_other |
              loopback | none | unknown
    """
    if not ip_str or ip_str in ("—", "?"):
        return "none"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # z. B. "2 Ziele" oder Doku-String
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


# ---------------------------------------------------------------------------
# Positiv-Events — echte Detektor-Ausgaben. Sollen hoch bewertet werden.
# ---------------------------------------------------------------------------

POSITIVE: list[dict] = [
    {
        "name": "POS #7 – syn_fan_out (Port-Scan, 23 Ports)",
        "detector": "syn_fan_out",
        "title": "SYN-Fächer: 192.168.0.194 → 192.168.0.1 (25 SYNs, 23 Ports/10s)",
        "src": "192.168.0.194",
        "dst": "192.168.0.1",
        "severity_hint": 8,
        "details": {
            "count": 25, "distinct_ports": 23,
            "sample_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143],
            "cooldown_s": 300,
        },
    },
    {
        "name": "POS #13 – syn_fan_out_multi (LAN-Scan, 2 Ziele)",
        "detector": "syn_fan_out_multi",
        "title": "LAN-Scan: 192.168.0.194 hat 2 LAN-Ziele auf 34 Ports in 10s kontaktiert",
        "src": "192.168.0.194",
        "dst": "2 Ziele",
        "severity_hint": 7,
        "details": {
            "targets": ["192.168.0.1", "192.168.0.214"],
            "distinct_targets": 2, "distinct_ports": 34,
            "total_syns": 41, "window_s": 10,
        },
    },
    {
        "name": "POS #36 – beaconing (CV 0.00, externer Host)",
        "detector": "beaconing",
        "title": "Beaconing: 192.168.0.42 → 1.1.1.1:443 (9 Intervalle, Ø 6.0 s, CV 0.00)",
        "src": "192.168.0.42",
        "dst": "1.1.1.1",
        "severity_hint": 7,
        "details": {
            "samples": 10, "mean_interval_s": 6.0, "stdev_interval_s": 0.02,
            "cv": 0.003, "dst_port": 443,
            "intervals_sample_s": [6.0, 6.0, 6.1, 6.0, 5.9],
        },
    },
]


# ---------------------------------------------------------------------------
# Negativ-Events — Detektor feuert, aber Verhalten ist harmlos.
# ---------------------------------------------------------------------------

NEGATIVE: list[dict] = [
    {
        "name": "NEG – NTP-Client alle 60s an Router",
        "detector": "beaconing",
        "title": "Beaconing: 192.168.0.42 → 192.168.0.1:123 (10 Intervalle, Ø 60.0 s, CV 0.05)",
        "src": "192.168.0.42",
        "dst": "192.168.0.1",
        "severity_hint": 7,
        "details": {
            "samples": 10, "mean_interval_s": 60.0, "stdev_interval_s": 3.0,
            "cv": 0.05, "dst_port": 123,
            "intervals_sample_s": [60.0, 58.2, 61.5, 59.8, 60.1],
        },
    },
    {
        "name": "NEG – DNS-Client alle 30s an Router",
        "detector": "beaconing",
        "title": "Beaconing: 192.168.0.77 → 192.168.0.1:53 (10 Intervalle, Ø 30.0 s, CV 0.08)",
        "src": "192.168.0.77",
        "dst": "192.168.0.1",
        "severity_hint": 7,
        "details": {
            "samples": 10, "mean_interval_s": 30.0, "stdev_interval_s": 2.4,
            "cv": 0.08, "dst_port": 53,
            "intervals_sample_s": [30.0, 28.5, 31.2, 29.8, 30.4],
        },
    },
    {
        "name": "NEG – Backup-Sync alle 300s an NAS",
        "detector": "beaconing",
        "title": "Beaconing: 192.168.0.42 → 192.168.0.10:445 (12 Intervalle, Ø 300.0 s, CV 0.02)",
        "src": "192.168.0.42",
        "dst": "192.168.0.10",
        "severity_hint": 7,
        "details": {
            "samples": 12, "mean_interval_s": 300.0, "stdev_interval_s": 6.0,
            "cv": 0.02, "dst_port": 445,
            "intervals_sample_s": [300.0, 298.5, 301.2, 299.8, 300.4],
        },
    },
    {
        "name": "NEG – DNS-over-TLS alle 30s an 1.1.1.1 (extern, grenzwertig)",
        "detector": "beaconing",
        "title": "Beaconing: 192.168.0.42 → 1.1.1.1:853 (10 Intervalle, Ø 30.0 s, CV 0.03)",
        "src": "192.168.0.42",
        "dst": "1.1.1.1",
        "severity_hint": 7,
        "details": {
            "samples": 10, "mean_interval_s": 30.0, "stdev_interval_s": 0.9,
            "cv": 0.03, "dst_port": 853,
            "intervals_sample_s": [30.0, 29.8, 30.2, 29.9, 30.1],
        },
    },
    {
        "name": "NEG – Steam-Update 200 MB (harmlos, hohes Volumen)",
        "detector": "high_volume",
        "title": "Hohe Datenrate: 192.168.0.42 → 23.62.99.180:443 (200.0 MB in 60 s)",
        "src": "192.168.0.42",
        "dst": "23.62.99.180",
        "severity_hint": 3,
        "details": {
            "bytes": 209715200, "mb": 200.0,
            "window_s": 60, "src_port": 51234, "dst_port": 443, "protocol": "tls",
        },
    },
    {
        "name": "NEG – Windows-Update 300 MB (harmlos, hohes Volumen)",
        "detector": "high_volume",
        "title": "Hohe Datenrate: 192.168.0.42 → 13.107.4.50:443 (300.0 MB in 60 s)",
        "src": "192.168.0.42",
        "dst": "13.107.4.50",
        "severity_hint": 3,
        "details": {
            "bytes": 314572800, "mb": 300.0,
            "window_s": 60, "src_port": 52111, "dst_port": 443, "protocol": "tls",
        },
    },
    {
        "name": "NEG – Browser öffnet 8 verschiedene Webseiten (harmlos)",
        "detector": "syn_fan_out",
        "title": "SYN-Fächer: 192.168.0.42 → 142.250.185.78 (28 SYNs, 8 Ports/10s)",
        "src": "192.168.0.42",
        "dst": "142.250.185.78",
        "severity_hint": 3,
        "details": {
            "count": 28, "distinct_ports": 8,
            "sample_ports": [443, 443, 443, 80, 80],
            "cooldown_s": 300,
        },
    },
    {
        "name": "NEG – DHCP-Renew / neues Gerät (harmlos)",
        "detector": "new_host",
        "title": "Neues Gerät: Apple (aa:bb:cc:dd:ee:ff) — 192.168.0.77",
        "src": "192.168.0.77",
        "dst": "",
        "severity_hint": 3,
        "details": {
            "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Apple",
            "first_ip": "192.168.0.77", "frame": 12345,
        },
    },
]


# ---------------------------------------------------------------------------
# State + Questions
# ---------------------------------------------------------------------------

def build_state(ev: dict, local_subnets: list[str] = LOCAL_SUBNETS) -> str:
    """Kompakter, englischer State mit expliziten Scope-Tags für src/dst."""
    scope_src = _target_scope(ev["src"], local_subnets)
    scope_dst = _target_scope(ev["dst"], local_subnets)
    return (
        f"detector={ev['detector']}\n"
        f"title={ev['title']}\n"
        f"src={ev['src']}  [scope={scope_src}]\n"
        f"dst={ev['dst']}  [scope={scope_dst}]\n"
        f"rule_hint={ev['severity_hint']}/10\n"
        f"details={json.dumps(ev['details'], ensure_ascii=False)}"
    )


def build_questions() -> dict:
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


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

async def call_decision(client: Any, state: str,
                        questions: dict) -> dict:
    payload = {
        "model":      DECISION_MODEL,
        "state":      state,
        "questions":  questions,
        "keep_alive": "24h",
    }
    r = await client.post(f"{OLLAMA}/v1/systemone", json=payload, timeout=120.0)
    r.raise_for_status()
    return r.json()


async def call_chat(client: Any, ev: dict) -> dict:
    prompt = (
        f"Detektor: {ev['detector']}\n"
        f"Titel: {ev['title']}\n"
        f"Quelle: {ev['src']}\n"
        f"Ziel: {ev['dst']}\n"
        f"Regel-Hinweis: {ev['severity_hint']}/10\n"
        f"Details: {json.dumps(ev['details'], ensure_ascii=False)}\n\n"
        'Antworte mit JSON: '
        '{"severity": <0-10>, '
        '"category": "<dns|connectivity|security|performance|discovery|unknown>", '
        '"explanation": "<max 2 Sätze>"}'
    )
    payload = {
        "model": CHAT_MODEL, "prompt": prompt, "stream": False,
        "format": "json", "keep_alive": "24h",
        "options": {"temperature": 0.1, "num_predict": 200, "num_ctx": 2048},
    }
    r = await client.post(f"{OLLAMA}/api/generate", json=payload, timeout=120.0)
    r.raise_for_status()
    data = r.json()
    raw = data.get("response", "")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {"_raw": raw, "_parse_error": True}
    return {"parsed": parsed,
            "duration_ms": int(data.get("total_duration", 0) / 1e6)}


# ---------------------------------------------------------------------------
# Print
# ---------------------------------------------------------------------------

def _fmt(v, digits: int = 2) -> str:
    if v is None:
        return "?"
    try:
        return f"{float(v):.{digits}f}"
    except (TypeError, ValueError):
        return str(v)


def print_decision(answers: dict) -> None:
    sev = answers.get("severity") or {}
    cat = answers.get("category") or {}

    score = sev.get("score")
    conf  = sev.get("confidence")
    print(f"    severity        : {_fmt(score)}   (confidence={_fmt(conf)})")

    probs = sev.get("probabilities")
    if isinstance(probs, dict) and probs:
        try:
            as_float = {int(k): float(v) for k, v in probs.items()}
        except (ValueError, TypeError):
            as_float = {}
        if as_float:
            top = sorted(as_float.items(), key=lambda x: x[1], reverse=True)[:4]
            print("      top probs     : "
                  + "  ".join(f"L{i}={p:.2f}" for i, p in top))
            mass_hi  = sum(p for i, p in as_float.items() if i >= 7)
            mass_mid = sum(p for i, p in as_float.items() if 5 <= i < 7)
            mass_lo  = sum(p for i, p in as_float.items() if i < 5)
            print(f"      P(sev>=7)={mass_hi:.2f}  P(5..6)={mass_mid:.2f}  "
                  f"P(<5)={mass_lo:.2f}")

    print(f"    category        : {cat.get('choice')}   "
          f"(confidence={_fmt(cat.get('confidence'))})")
    cat_probs = cat.get("probabilities")
    if isinstance(cat_probs, dict) and cat_probs:
        top = sorted(cat_probs.items(), key=lambda x: x[1], reverse=True)[:3]
        print("      top probs     : "
              + "  ".join(f"{k}={_fmt(v)}" for k, v in top))

    is_scan      = (answers.get("is_scan")                or {}).get("noul")
    is_beaconing = (answers.get("is_beaconing")           or {}).get("noul")
    is_external  = (answers.get("is_external_destination") or {}).get("noul")
    print(f"    is_scan         : {_fmt(is_scan, 3)}")
    print(f"    is_beaconing    : {_fmt(is_beaconing, 3)}")
    print(f"    is_external     : {_fmt(is_external, 3)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compare", action="store_true")
    ap.add_argument("--raw",     action="store_true")
    ap.add_argument("--only",    type=str, default=None)
    ap.add_argument("--neg",     action="store_true")
    ap.add_argument("--all",     action="store_true")
    args = ap.parse_args()

    async with httpx.AsyncClient() as client:
        try:
            tags = await client.get(f"{OLLAMA}/api/tags", timeout=5.0)
            tags.raise_for_status()
            installed = {m["name"] for m in tags.json().get("models", [])}
        except Exception as e:
            print(f"[FEHLER] Ollama nicht erreichbar unter {OLLAMA}: {e}")
            return 1

        print(f"Ollama:               {OLLAMA}")
        print(f"Installierte Modelle: {sorted(installed)}")

        if DECISION_MODEL not in installed:
            print(f"\n[FEHLER] {DECISION_MODEL} nicht installiert.")
            print(f"         ollama pull {DECISION_MODEL}")
            return 2

        if args.compare and CHAT_MODEL not in installed:
            print(f"[WARN]   {CHAT_MODEL} nicht installiert — --compare aus.")
            args.compare = False

        if args.all:
            events = POSITIVE + NEGATIVE
        elif args.neg:
            events = list(NEGATIVE)
        else:
            events = list(POSITIVE)

        if args.only:
            events = [e for e in events
                      if args.only.lower() in e["name"].lower()]

        questions = build_questions()

        print(f"\n{len(events)} Events"
              + (f", Chat-Model={CHAT_MODEL}" if args.compare else ""))
        print("=" * 78)

        for ev in events:
            scope_src = _target_scope(ev["src"])
            scope_dst = _target_scope(ev["dst"])

            print(f"\n{ev['name']}")
            print(f"  detector={ev['detector']}  hint={ev['severity_hint']}")
            print(f"  src={ev['src']} [{scope_src}]  →  "
                  f"dst={ev['dst']} [{scope_dst}]")

            state = build_state(ev)

            t0 = time.monotonic()
            try:
                resp = await call_decision(client, state, questions)
            except httpx.HTTPStatusError as e:
                print(f"  [FEHLER] HTTP {e.response.status_code}: "
                      f"{e.response.text[:300]}")
                continue
            except Exception as e:
                print(f"  [FEHLER] {type(e).__name__}: {e}")
                continue
            dt_ms = (time.monotonic() - t0) * 1000

            print(f"\n  ── Tev1 ({dt_ms:.0f} ms) ──")

            answers = resp.get("answers") or resp

            if args.raw:
                print("  RAW response:")
                print("    " + json.dumps(resp, indent=4, ensure_ascii=False)
                              .replace("\n", "\n    "))

            print_decision(answers)

            if args.compare:
                t0 = time.monotonic()
                try:
                    chat = await call_chat(client, ev)
                    dt_ms = (time.monotonic() - t0) * 1000
                    print(f"\n  ── Chat ({CHAT_MODEL}, {dt_ms:.0f} ms) ──")
                    for k, v in chat["parsed"].items():
                        print(f"    {k:13s}: {v}")
                except httpx.HTTPStatusError as e:
                    print(f"  [CHAT FEHLER] HTTP {e.response.status_code}: "
                          f"{e.response.text[:200]}")

            print()

        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))