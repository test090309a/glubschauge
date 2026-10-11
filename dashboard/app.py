# dashboard/app.py
from dash import Dash, dcc, html, Input, Output, State, callback
import dash_bootstrap_components as dbc
from dashboard.data import get_recent_events, get_host_inventory
from dashboard.components import (create_stat_card, create_event_table, create_severity_chart)

# 1. App initialisieren mit einem professionellen Theme
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, dbc.icons.FONT_AWESOME])

# 2. Das Haupt-Layout definieren
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col(html.H1("Glubschauge – Netzwerk-Monitor", className="text-center my-4"), width=12)
    ]),

    # KPI Cards (Statistiken auf einen Blick)
    dbc.Row([
        dbc.Col(create_stat_card("Aktive Hosts", "12", "fa-network-wired"), width=3),
        dbc.Col(create_stat_card("Events (24h)", "1.234", "fa-exclamation-triangle"), width=3),
        dbc.Col(create_stat_card("Kritische Events", "3", "fa-fire", "danger"), width=3),
        dbc.Col(create_stat_card("Ø Latenz", "12ms", "fa-tachometer-alt"), width=3),
    ], className="mb-4"),

    # Hauptbereich: 2 Spalten
    dbc.Row([
        # Linke Spalte: Event-Feed
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Aktuelle Events"),
                dbc.CardBody(create_event_table(get_recent_events()))
            ])
        ], width=8),

        # Rechte Spalte: Charts & Statistiken
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Event-Verteilung nach Schweregrad"),
                dbc.CardBody(dcc.Graph(id="severity-chart"))
            ]),
            dbc.Card([
                dbc.CardHeader("Top-Geräte nach Events"),
                dbc.CardBody(dcc.Graph(id="top-hosts-chart"))
            ])
        ], width=4),
    ]),

    # Ein Intervall, um die Daten regelmäßig zu aktualisieren
    dcc.Interval(id="refresh-interval", interval=5*1000) # alle 5 Sekunden
], fluid=True)

# 3. Callbacks für Interaktivität
@callback(
    Output("event-table-container", "children"),
    Output("severity-chart", "figure"),
    Input("refresh-interval", "n_intervals")
)
def update_dashboard(n):
    events_df = get_recent_events()
    # ... erstelle Figur für severity_chart ...
    return create_event_table(events_df), severity_fig