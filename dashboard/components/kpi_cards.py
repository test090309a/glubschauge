"""KPI-Karten für das Dashboard."""
from dash import html
import dash_bootstrap_components as dbc


def stat_card(title: str, value: str, icon: str, color: str = "info") -> dbc.Card:
    return dbc.Card(
        dbc.CardBody([
            dbc.Row([
                dbc.Col([
                    html.Div(title, className="text-muted small text-uppercase mb-1"),
                    html.H3(value, className="mb-0 text-white"),
                ], width=8),
                dbc.Col(
                    html.I(className=f"fas {icon} fa-2x text-{color}"),
                    width=4, className="text-end d-flex align-items-center justify-content-end",
                ),
            ], align="center"),
        ]),
        className="h-100 shadow-sm bg-dark border-secondary",
    )