"""Event-Tabelle für das Dashboard."""
from __future__ import annotations

import pandas as pd
from dash import html
import dash_bootstrap_components as dbc


_SEV_COLORS = [
    (9, "#dc3545"),   # rot
    (7, "#fd7e14"),   # orange
    (5, "#ffc107"),   # gelb
    (3, "#17a2b8"),   # cyan
    (1, "#28a745"),   # grün
    (0, "#6c757d"),   # grau
]


def severity_color(sev: int) -> str:
    for threshold, color in _SEV_COLORS:
        if sev >= threshold:
            return color
    return "#6c757d"


def event_table(df: pd.DataFrame, max_rows: int = 20) -> html.Div:
    if df.empty:
        return html.Div("Keine Events vorhanden.", className="text-muted p-3")

    rows = []
    for _, row in df.head(max_rows).iterrows():
        sev_raw = row.get("llm_severity")
        if sev_raw is None or pd.isna(sev_raw):
            sev_raw = row.get("severity_hint", 0)
        sev = int(sev_raw)
        color = severity_color(sev)
        ts = str(row["ts"])[11:19]
        title = str(row["title"])
        detector = str(row["detector"])

        rows.append(html.Tr([
            html.Td(ts, style={"fontFamily": "monospace", "fontSize": "0.85em"}),
            html.Td(
                html.Span(str(sev), className="badge",
                          style={"backgroundColor": color, "minWidth": "28px"}),
                style={"width": "50px"},
            ),
            html.Td(detector, style={"fontFamily": "monospace", "fontSize": "0.8em"}),
            html.Td(title, style={"fontSize": "0.9em"}),
        ]))

    return dbc.Table([
        html.Thead(html.Tr([
            html.Th("Zeit", style={"width": "80px"}),
            html.Th("Sev", style={"width": "50px"}),
            html.Th("Detektor", style={"width": "140px"}),
            html.Th("Titel"),
        ])),
        html.Tbody(rows),
    ], striped=True, hover=True, responsive=True, size="sm",
       className="mb-0", color="dark")