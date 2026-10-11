"""Host-Inventar & Topologie."""
import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

from data import get_hosts, get_topology_elements
from components.host_inventory import host_table
from components.header import page_header

dash.register_page(__name__, path="/hosts", name="Hosts")


# Stylesheet: dezente Labels, klare Farben, fester Look
_CYTO_STYLESHEET = [
    # --- Nodes ------------------------------------------------------------
    {
        "selector": "node",
        "style": {
            "label":            "data(label)",
            "color":            "#b8b8b8",
            "font-size":        "10px",
            "font-family":      "monospace",
            "font-weight":      "normal",
            "text-wrap":        "wrap",
            "text-max-width":   "110px",
            "text-valign":      "bottom",
            "text-halign":      "center",
            "text-margin-y":    6,
            "text-outline-width": 0,
            "width":            "26px",
            "height":           "26px",
            "border-width":     1,
            "border-color":     "#000",
            "border-opacity":   0.5,
        },
    },
    # --- Router -----------------------------------------------------------
    {
        "selector": ".router",
        "style": {
            "background-color": "#ffc107",
            "width":  "48px",
            "height": "48px",
            "color":  "#ffc107",
            "font-size": "11px",
            "font-weight": "bold",
        },
    },
    # --- Status-Farben ----------------------------------------------------
    {"selector": ".online",  "style": {"background-color": "#28a745", "opacity": 1.0}},
    {"selector": ".idle",    "style": {"background-color": "#ffc107", "opacity": 0.85}},
    {"selector": ".offline", "style": {"background-color": "#4a4a4a", "opacity": 0.55}},
    # --- Edges ------------------------------------------------------------
    {
        "selector": "edge",
        "style": {
            "line-color":  "#333",
            "width":       1.5,
            "curve-style": "bezier",
            "opacity":     0.6,
        },
    },
    {"selector": "edge.online",  "style": {"line-color": "#28a745", "opacity": 0.55}},
    {"selector": "edge.idle",    "style": {"line-color": "#ffc107", "opacity": 0.35}},
    {"selector": "edge.offline", "style": {"line-color": "#2a2a2a", "opacity": 0.20}},
]


def layout(**_kwargs):
    return html.Div([
        page_header("Hosts & Topologie", "Alle bekannten Geräte im Netzwerk"),

        dbc.Row([
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Netzwerk-Topologie"),
                    dbc.CardBody(
                        cyto.Cytoscape(
                            id="topology",
                            elements=[],
                            # preset = keine Physik, keine Neuberechnung,
                            # Positionen kommen vom Server (Kreis um Router).
                            layout={
                                "name":    "preset",
                                "fit":     True,
                                "padding": 40,
                                "animate": False,
                            },
                            style={
                                "width":  "100%",
                                "height": "560px",
                                "backgroundColor": "#0d0d0d",
                            },
                            stylesheet=_CYTO_STYLESHEET,
                            wheelSensitivity=0.3,
                            minZoom=0.4,
                            maxZoom=2.0,
                        ),
                        style={"minHeight": "580px"},
                    ),
                ], className="h-100 bg-dark border-secondary"),
                width=7,
            ),
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Host-Inventar"),
                    dbc.CardBody(id="host-table-body",
                                 style={"maxHeight": "580px", "overflowY": "auto"}),
                ], className="h-100 bg-dark border-secondary"),
                width=5,
            ),
        ], className="g-3"),

        # Zwei getrennte Intervalle:
        #   * Tabelle: 5 s (reiner Text, günstig)
        #   * Topologie: 20 s (stabil, kein unnötiges Re-Render)
        dcc.Interval(id="host-table-refresh", interval=5000,  n_intervals=0),
        dcc.Interval(id="topology-refresh",   interval=20000, n_intervals=0),
    ])


@callback(
    Output("host-table-body", "children"),
    Input("host-table-refresh", "n_intervals"),
)
def _update_table(_n):
    return host_table(get_hosts())


@callback(
    Output("topology", "elements"),
    Input("topology-refresh", "n_intervals"),
)
def _update_topology(_n):
    return get_topology_elements()