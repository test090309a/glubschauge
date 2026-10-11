"""Markdown-Export von Events."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _sev_label(sev: int) -> str:
    if sev >= 8: return "🔴 kritisch"
    if sev >= 6: return "🟠 verdächtig"
    if sev >= 4: return "🟡 beobachten"
    if sev >= 2: return "🟢 normal"
    return "⚪ harmlos"


def export_events_markdown(
    events: list[dict],
    out_dir: str | Path = "reports",
    min_severity: int = 0,
    filename: str | None = None,
) -> Path:
    """Schreibt gefilterte Events als Markdown-Report. Liefert den Pfad."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if filename is None:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename = f"report_{ts}.md"
    out_path = out_dir / filename

    now = datetime.now(timezone.utc).astimezone()
    lines: list[str] = []

    # --- Header --------------------------------------------------------
    lines.append(f"# glubschauge Report – {now.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append(f"- **Events im Report:** {len(events)}")
    lines.append(f"- **Severity-Filter:** {'≥ ' + str(min_severity) if min_severity else 'aus'}")
    if events:
        ts_first = events[-1]["ts"][:19]
        ts_last  = events[0]["ts"][:19]
        lines.append(f"- **Zeitraum:** {ts_first} bis {ts_last}")
    lines.append("")

    # --- Übersichtstabelle --------------------------------------------
    lines.append("## Übersicht")
    lines.append("")
    lines.append("| # | Zeit | Sev | Detektor | Titel |")
    lines.append("|---|------|-----|----------|-------|")
    for e in events:
        ts   = e["ts"][11:19]
        sev  = e["llm_severity"] if e["llm_severity"] is not None else e["severity_hint"]
        det  = e["detector"]
        title = e["title"].replace("|", "\\|")
        lines.append(f"| {e['id']} | {ts} | {sev} | `{det}` | {title} |")
    lines.append("")

    # --- Detail-Sektion pro Event -------------------------------------
    lines.append("## Details")
    lines.append("")
    for e in events:
        lines.append(f"### #{e['id']} — {e['title']}")
        lines.append("")
        lines.append(f"- **Zeit:** `{e['ts']}`")
        lines.append(f"- **Detektor:** `{e['detector']}`")
        lines.append(f"- **Regel-Hint:** {e['severity_hint']}/10")
        lines.append(f"- **Quelle:** `{e['src'] or '—'}`")
        lines.append(f"- **Ziel:** `{e['dst'] or '—'}`")

        if e["llm_severity"] is not None:
            lines.append(
                f"- **LLM:** {e['llm_severity']}/10 "
                f"{_sev_label(e['llm_severity'])} "
                f"({e['llm_category']}, {e['llm_model']}, {e['llm_duration_ms']} ms)"
            )
            lines.append(f"- **Erklärung:** {e['llm_explanation']}")
        else:
            lines.append("- **LLM:** *noch keine Bewertung*")
        lines.append("")

        # Details-JSON schön formatiert
        try:
            details_obj = json.loads(e["details"]) if e.get("details") else {}
        except (json.JSONDecodeError, TypeError):
            details_obj = {"raw": str(e.get("details", ""))}
        if details_obj:
            lines.append("**Details:**")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(details_obj, indent=2, ensure_ascii=False))
            lines.append("```")
            lines.append("")
        lines.append("---")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path