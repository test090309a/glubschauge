"""Host-Inventar & Topologie."""
import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

from data import get_hosts, get_topology_elements
from components.host_inventory import host_table
from components.header import page_header

dash.register_page(__name__, path="/hosts", name="Hosts")


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
                            layout={"name": "cose", "animate": True},
                            style={"width": "100%", "height": "520px",
                                   "backgroundColor": "#0f0f0f"},
                            stylesheet=[
                                {"selector": "node",
                                "style": {"label": "data(label)",
                                        "color": "#e0e0e0",
                                        "font-size": "11px",
                                        "text-wrap": "wrap",
                                        "text-max-width": "100px",
                                        "width": "40px",
                                        "height": "40px"}},
                                {"selector": ".router",
                                "style": {"background-color": "#ffc107",
                                        "width": "60px", "height": "60px"}},

                                # Online → grün
                                {"selector": ".online",
                                "style": {"background-color": "#28a745",
                                        "opacity": 1.0}},
                                # Idle → gelb-orange
                                {"selector": ".idle",
                                "style": {"background-color": "#ffc107",
                                        "opacity": 0.85}},
                                # Offline → grau, halbtransparent
                                {"selector": ".offline",
                                "style": {"background-color": "#4a4a4a",
                                        "opacity": 0.5}},

                                {"selector": "edge",
                                "style": {"line-color": "#444", "width": 1.5,
                                        "curve-style": "bezier"}},
                                {"selector": "edge.online",
                                "style": {"line-color": "#28a745", "opacity": 0.6}},
                                {"selector": "edge.idle",
                                "style": {"line-color": "#ffc107", "opacity": 0.3}},
                                {"selector": "edge.offline",
                                "style": {"line-color": "#333", "opacity": 0.2}},
                            ],
                        ),
                        style={"minHeight": "540px"},
                    ),
                ], className="h-100 bg-dark border-secondary"),
                width=7,
            ),
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Host-Inventar"),
                    dbc.CardBody(id="host-table-body",
                                 style={"maxHeight": "540px", "overflowY": "auto"}),
                ], className="h-100 bg-dark border-secondary"),
                width=5,
            ),
        ], className="g-3"),

        dcc.Interval(id="hosts-refresh", interval=5000, n_intervals=0),
    ])


@callback(
    Output("host-table-body", "children"),
    Output("topology", "elements"),
    Input("hosts-refresh", "n_intervals"),
)
def _update(_n):
    df = get_hosts()
    return host_table(df), get_topology_elements()