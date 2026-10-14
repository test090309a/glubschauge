"""Host-Inventar & Topologie mit Detail-Drawer für Klicks."""
import dash
from dash import html, dcc, callback, Input, Output, State
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

from data import get_hosts, get_topology_elements, get_host_details
from components.host_inventory import host_table
from components.header import page_header

dash.register_page(__name__, path="/hosts", name="Hosts")

_CYTO_STYLESHEET = [
    {
        "selector": "node",
        "style": {
            "label": "data(label)",
            "color": "#b8b8b8",
            "font-size": "10px",
            "font-family": "monospace",
            "text-wrap": "wrap",
            "text-max-width": "110px",
            "text-valign": "bottom",
            "text-halign": "center",
            "text-margin-y": 6,
            "width": "28px",
            "height": "28px",
            "border-width": 1,
            "border-color": "#000",
            "cursor": "pointer",
        },
    },
    {
        "selector": ":selected",
        "style": {
            "border-width": 3,
            "border-color": "#00bc8c",
            "shadow-blur": 10,
            "shadow-color": "#00bc8c",
        }
    },
    {
        "selector": ".router",
        "style": {
            "background-color": "#ffc107",
            "width": "48px",
            "height": "48px",
            "color": "#ffc107",
            "font-size": "11px",
            "font-weight": "bold",
        },
    },
    {"selector": ".online", "style": {"background-color": "#28a745", "opacity": 1.0}},
    {"selector": ".idle", "style": {"background-color": "#ffc107", "opacity": 0.85}},
    {"selector": ".offline", "style": {"background-color": "#4a4a4a", "opacity": 0.55}},
    {
        "selector": "edge",
        "style": {"line-color": "#333", "width": 1.5, "curve-style": "bezier", "opacity": 0.6},
    },
    {"selector": "edge.online", "style": {"line-color": "#28a745", "opacity": 0.55}},
    {"selector": "edge.idle", "style": {"line-color": "#ffc107", "opacity": 0.35}},
    {"selector": "edge.offline", "style": {"line-color": "#2a2a2a", "opacity": 0.20}},
]


def layout(**_kwargs):
    return html.Div([
        page_header("Hosts & Topologie", "Klicke auf einen Rechner für Ports, Dienste & Details"),

        dbc.Row([
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Netzwerk-Topologie (Klick auf Rechner)"),
                    dbc.CardBody(
                        cyto.Cytoscape(
                            id="topology",
                            elements=[],
                            layout={"name": "preset", "fit": True, "padding": 40, "animate": False},
                            style={"width": "100%", "height": "580px", "backgroundColor": "#0d0d0d"},
                            stylesheet=_CYTO_STYLESHEET,
                            wheelSensitivity=0.3,
                            minZoom=0.4,
                            maxZoom=2.0,
                        ),
                        style={"minHeight": "600px"},
                    ),
                ], className="h-100 bg-dark border-secondary"),
                width=7,
            ),
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Host-Inventar"),
                    dbc.CardBody(id="host-table-body", style={"maxHeight": "600px", "overflowY": "auto"}),
                ], className="h-100 bg-dark border-secondary"),
                width=5,
            ),
        ], className="g-3"),

        # --- Detail-Drawer (Offcanvas rechts) ---
        dbc.Offcanvas(
            id="host-details-drawer",
            title="Rechner-Details",
            is_open=False,
            placement="end",
            style={"width": "460px", "backgroundColor": "#121212", "color": "#e0e0e0"},
            children=html.Div(id="host-details-content"),
        ),

        dcc.Interval(id="host-table-refresh", interval=5000, n_intervals=0),
        dcc.Interval(id="topology-refresh", interval=20000, n_intervals=0),
    ])


@callback(Output("host-table-body", "children"), Input("host-table-refresh", "n_intervals"))
def _update_table(_n):
    return host_table(get_hosts())


@callback(Output("topology", "elements"), Input("topology-refresh", "n_intervals"))
def _update_topology(_n):
    return get_topology_elements()


# --- Klick-Handler für Cytoscape ---
@callback(
    Output("host-details-drawer", "is_open"),
    Output("host-details-content", "children"),
    Input("topology", "tapNodeData"),
    prevent_initial_call=True,
)
def _on_node_click(node_data):
    if not node_data or node_data.get("id") == "router":
        return False, dash.no_update

    mac = node_data.get("mac")
    details = get_host_details(mac)
    if not details:
        return True, html.P("Keine weiteren Detail-Informationen verfügbar.", className="text-muted")

    # 1. Ports & Services Badges / Liste
    if details["ports"]:
        port_items = []
        for p in details["ports"]:
            port_items.append(
                dbc.ListGroupItem([
                    html.Div([
                        html.Span(f"{p['port']}/{p['proto'].upper()}", className="badge bg-primary me-2 font-monospace"),
                        html.Strong(p["service"] or "Unbekannter Dienst", className="text-light"),
                    ], className="d-flex align-items-center justify-content-between"),
                    html.Small(f"Zuletzt aktiv: {p['last_seen'][11:19]}", className="text-muted d-block mt-1"),
                ], className="bg-dark border-secondary text-light py-2")
            )
        ports_card = dbc.ListGroup(port_items, flush=True)
    else:
        ports_card = html.Div([
            html.I(className="fas fa-search me-2 text-warning"),
            "Noch keine offenen Ports beobachtet (Rechner lauscht nicht oder noch kein Traffic).",
        ], className="text-muted small p-2 border border-secondary rounded")

    # 2. Letzte Events
    if details["events"]:
        event_rows = []
        for ev in details["events"]:
            sev_color = "danger" if ev["sev"] >= 7 else ("warning" if ev["sev"] >= 4 else "info")
            event_rows.append(
                html.Div([
                    html.Span(str(ev["sev"]), className=f"badge bg-{sev_color} me-2"),
                    html.Span(ev["title"], className="small text-truncate"),
                ], className="d-flex align-items-center mb-1 text-light")
            )
        events_card = html.Div(event_rows)
    else:
        events_card = html.Small("Keine Sicherheits-Events registriert.", className="text-muted")

    # Gesamter Drawer-Inhalt
    content = html.Div([
        # Header
        html.Div([
            html.H4(details["vendor"], className="mb-0 text-white font-weight-bold"),
            html.Span(
                f"● {details['status'].upper()}",
                style={"color": details["status_color"], "fontWeight": "bold", "fontSize": "0.9em"}
            ),
        ], className="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary"),

        # IP & MAC
        dbc.Card([
            dbc.CardBody([
                html.Div([html.Strong("MAC: "), html.Span(details["mac"], className="font-monospace text-info")]),
                html.Div([html.Strong("IP(s): "), html.Span(", ".join(details["ips"]), className="font-monospace text-warning")]),
                html.Div([html.Strong("Zuletzt gesehen: "), html.Span(details["last_seen"] or "—", className="small text-muted")]),
            ], className="py-2"),
        ], className="bg-dark border-secondary mb-3"),

        # Dienste & Ports
        html.H6([html.I(className="fas fa-network-wired me-2 text-info"), "Offene Ports & Dienste"], className="text-uppercase text-muted mt-3 mb-2"),
        ports_card,

        # Events
        html.H6([html.I(className="fas fa-shield-alt me-2 text-danger"), "Letzte Sicherheits-Events"], className="text-uppercase text-muted mt-4 mb-2"),
        events_card,
    ])

    return True, content