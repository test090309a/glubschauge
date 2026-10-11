"""Host-Inventar-Tabelle mit Online-Status."""
from __future__ import annotations

import pandas as pd
from dash import html
import dash_bootstrap_components as dbc


def _status_dot(status: str, color: str) -> html.Span:
    return html.Span(
        "●",
        style={
            "color": color,
            "fontSize": "1.1em",
            "marginRight": "6px",
            "textShadow": f"0 0 6px {color}",
        },
        title=status,
    )


def host_table(df: pd.DataFrame) -> html.Div:
    if df.empty:
        return html.Div("Keine Hosts erfasst.", className="text-muted p-3")

    rows = []
    for _, row in df.iterrows():
        last = str(row["last_seen"])[11:19] if row["last_seen"] else "—"
        ips = (row["ips"] or "").split(", ")
        ip_str = ips[0] if ips else "—"
        if len(ips) > 1:
            ip_str = f"{ip_str}  (+{len(ips) - 1})"

        status = row.get("status", "offline")
        color  = row.get("status_color", "#6c757d")

        rows.append(html.Tr([
            html.Td(
                html.Div([
                    _status_dot(status, color),
                    html.Span(status, style={"fontSize": "0.8em",
                                             "color": "#999"}),
                ]),
                style={"width": "80px"},
            ),
            html.Td(str(row["vendor"] or "—"),
                    style={"fontSize": "0.9em"}),
            html.Td(str(row["mac"]),
                    style={"fontFamily": "monospace", "fontSize": "0.8em"}),
            html.Td(ip_str,
                    style={"fontFamily": "monospace", "fontSize": "0.8em"}),
            html.Td(
                html.Span(str(int(row["event_count"])),
                          className="badge bg-secondary"),
                style={"textAlign": "center", "width": "70px"},
            ),
            html.Td(last,
                    style={"fontFamily": "monospace", "fontSize": "0.8em"}),
        ]))

    return dbc.Table([
        html.Thead(html.Tr([
            html.Th("Status",   style={"width": "80px"}),
            html.Th("Vendor"),
            html.Th("MAC"),
            html.Th("IPs"),
            html.Th("Events",   style={"textAlign": "center"}),
            html.Th("Zuletzt"),
        ])),
        html.Tbody(rows),
    ], striped=True, hover=True, responsive=True, size="sm",
       className="mb-0", color="dark")