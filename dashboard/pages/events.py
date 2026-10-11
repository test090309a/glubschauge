"""Detaillierte Event-Ansicht mit Filter."""
import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc

from data import get_events_filtered, get_detector_names
from components.event_feed import event_table
from components.header import page_header

dash.register_page(__name__, path="/events", name="Events")


def layout(**_kwargs):
    return html.Div([
        page_header("Events", "Volltext-Filter und Severity-Suche"),

        dbc.Card([
            dbc.CardBody([
                dbc.Row([
                    dbc.Col([
                        html.Label("Minimale Severity", className="text-muted small"),
                        dcc.Slider(id="sev-slider", min=0, max=10, step=1, value=0,
                                   marks={i: str(i) for i in range(0, 11, 2)}),
                    ], width=8),
                    dbc.Col([
                        html.Label("Detektor", className="text-muted small"),
                        dcc.Dropdown(
                            id="detector-dropdown",
                            options=[{"label": d, "value": d}
                                     for d in get_detector_names()],
                            value="alle", clearable=False,
                            className="text-dark",
                        ),
                    ], width=4),
                ]),
            ]),
        ], className="mb-3 bg-dark border-secondary"),

        dbc.Card([
            dbc.CardHeader(id="events-count-header", children="Lade …"),
            dbc.CardBody(id="events-table-body",
                         style={"maxHeight": "600px", "overflowY": "auto"}),
        ], className="bg-dark border-secondary"),

        dcc.Interval(id="events-refresh", interval=10000, n_intervals=0),
    ])


@callback(
    Output("events-table-body", "children"),
    Output("events-count-header", "children"),
    Input("sev-slider", "value"),
    Input("detector-dropdown", "value"),
    Input("events-refresh", "n_intervals"),
)
def _update(min_sev, detector, _n):
    df = get_events_filtered(min_severity=min_sev, detector=detector, limit=500)
    header = f"{len(df)} Events (Severity ≥ {min_sev}, Detektor: {detector})"
    return event_table(df, max_rows=500), header