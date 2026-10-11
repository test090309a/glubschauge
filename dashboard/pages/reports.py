"""Reports-Verwaltung."""
from pathlib import Path

import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc

from components.header import page_header

dash.register_page(__name__, path="/reports", name="Reports")

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports"


def layout(**_kwargs):
    return html.Div([
        page_header("Reports", "Markdown-Exporte aus glubschauge"),

        dbc.Card([
            dbc.CardHeader("Verfügbare Reports"),
            dbc.CardBody(id="reports-body"),
        ], className="bg-dark border-secondary"),

        dcc.Interval(id="reports-refresh", interval=10000, n_intervals=0),
    ])


@callback(Output("reports-body", "children"), Input("reports-refresh", "n_intervals"))
def _update(_n):
    if not REPORTS_DIR.exists():
        return html.Div("Reports-Ordner existiert noch nicht. "
                        "Erzeuge einen Report mit `e` in der TUI.",
                        className="text-muted")

    files = sorted(REPORTS_DIR.glob("report_*.md"),
                   key=lambda p: p.stat().st_mtime, reverse=True)

    if not files:
        return html.Div("Keine Reports vorhanden. Drücke `e` in der TUI, "
                        "um einen zu erzeugen.", className="text-muted")

    rows = []
    for f in files[:50]:
        size_kb = f.stat().st_size / 1024
        mtime = f.stat().st_mtime
        from datetime import datetime
        ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        rows.append(html.Tr([
            html.Td(html.A(f.name, href=f"/assets/reports/{f.name}",
                           target="_blank",
                           style={"fontFamily": "monospace"})),
            html.Td(ts, style={"fontFamily": "monospace", "fontSize": "0.85em"}),
            html.Td(f"{size_kb:.1f} KB", style={"textAlign": "right"}),
        ]))

    return dbc.Table([
        html.Thead(html.Tr([
            html.Th("Datei"), html.Th("Erstellt"), html.Th("Größe",
                                                          style={"textAlign": "right"}),
        ])),
        html.Tbody(rows),
    ], striped=True, hover=True, size="sm", className="mb-0", color="dark")