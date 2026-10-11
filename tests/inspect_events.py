"""Zeigt die letzten Events samt LLM-Bewertung."""
import sqlite3
from pathlib import Path

DB = Path("glubschauge.db")
if not DB.exists():
    print(f"{DB} existiert nicht – bitte erst run.py ausführen.")
    raise SystemExit(1)

conn = sqlite3.connect(DB)
rows = conn.execute("""
    SELECT e.id, e.ts, e.detector, e.severity_hint, e.title,
           v.severity, v.category, v.explanation, v.duration_ms
    FROM events e
    LEFT JOIN event_evaluations v ON v.event_id = e.id
    ORDER BY e.id DESC
    LIMIT 30
""").fetchall()

print(f"{'ID':>4}  {'Zeit':<19}  {'Regel':<18}  {'Hint':>4}  "
      f"{'LLM':>3}  {'Kategorie':<13}  {'ms':>5}  Titel / Erklärung")
print("─" * 140)
for r in rows:
    (eid, ts, det, hint, title, sev, cat, expl, dur) = r
    llm = f"{sev:>3}" if sev is not None else "  –"
    cat = (cat or "–")[:12]
    dur_s = f"{dur:>5}" if dur else "    –"
    print(f"{eid:>4}  {ts[:19]:<19}  {det:<18}  {hint:>4}  {llm}  {cat:<13}  {dur_s}  {title}")
    if expl:
        print(f"      └─ {expl}")