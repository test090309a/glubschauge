"""glubschauge Dashboard – Dash-App."""
from __future__ import annotations

import sys
from pathlib import Path

# Sicherstellen, dass `data`, `components` und `pages` importierbar sind
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dash
from dash import Dash, dcc, html
import dash_bootstrap_components as dbc
from dash_bootstrap_templates import load_figure_template

load_figure_template(["cyborg", "darkly"])

app = Dash(
    __name__,
    use_pages=True,
    external_stylesheets=[dbc.themes.CYBORG, dbc.icons.FONT_AWESOME],
    suppress_callback_exceptions=True,
    title="glubschauge",
)

navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(dbc.NavLink("Übersicht", href="/",     active="exact")),
        dbc.NavItem(dbc.NavLink("Hosts",     href="/hosts", active="exact")),
        dbc.NavItem(dbc.NavLink("Events",    href="/events", active="exact")),
        dbc.NavItem(dbc.NavLink("Reports",   href="/reports", active="exact")),
    ],
    brand=html.Span([html.I(className="fas fa-eye me-2"), "glubschauge"]),
    brand_href="/",
    color="dark",
    dark=True,
    className="mb-4 border-bottom border-secondary",
)

app.layout = dbc.Container([
    dcc.Location(id="url"),
    navbar,
    dash.page_container,
], fluid=True, style={"padding": "0 1.5rem"})


if __name__ == "__main__":
    app.run(debug=True, port=8050, host="127.0.0.1")