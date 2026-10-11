"""Übersichtsseite."""
import dash
from dash import html, dcc, callback, Input, Output
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go

from data import (get_kpis, get_recent_events, get_severity_distribution,
                  get_top_hosts, get_event_timeline)
from components.kpi_cards import stat_card
from components.event_feed import event_table, severity_color
from components.header import page_header

dash.register_page(__name__, path="/", name="Übersicht")


def layout(**_kwargs):
    return html.Div([
        page_header("Übersicht", "Netzwerk-Monitor mit lokaler KI"),

        dbc.Row(id="kpi-row", className="mb-4 g-3"),

        dbc.Row([
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Aktuelle Events"),
                    dbc.CardBody(id="event-feed-body",
                                 style={"maxHeight": "520px", "overflowY": "auto"}),
                ], className="h-100 bg-dark border-secondary"),
                width=7,
            ),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Verteilung nach Schweregrad"),
                    dbc.CardBody(dcc.Graph(id="severity-chart",
                                           config={"displayModeBar": False})),
                ], className="mb-3 bg-dark border-secondary"),
                dbc.Card([
                    dbc.CardHeader("Top Hosts nach Events"),
                    dbc.CardBody(dcc.Graph(id="top-hosts-chart",
                                           config={"displayModeBar": False})),
                ], className="bg-dark border-secondary"),
            ], width=5),
        ], className="mb-4 g-3"),

        dbc.Row(
            dbc.Col(
                dbc.Card([
                    dbc.CardHeader("Events im Zeitverlauf (24 h)"),
                    dbc.CardBody(dcc.Graph(id="timeline-chart",
                                           config={"displayModeBar": False})),
                ], className="bg-dark border-secondary"),
                width=12,
            ),
        ),

        dcc.Interval(id="refresh", interval=5000, n_intervals=0),
    ])


@callback(Output("kpi-row", "children"), Input("refresh", "n_intervals"))
def _update_kpis(_n):
    k = get_kpis()
    return [
        dbc.Col(stat_card("Aktive Hosts",     str(k["active_hosts"]),
                          "fa-network-wired", "info"), width=3),
        dbc.Col(stat_card("Events (24 h)",    str(k["events_24h"]),
                          "fa-list",          "primary"), width=3),
        dbc.Col(stat_card("Kritisch (24 h)",  str(k["critical_events"]),
                          "fa-fire",          "danger"), width=3),
        dbc.Col(stat_card("Neue Hosts (24 h)", str(k["new_hosts_24h"]),
                          "fa-user-plus",     "success"), width=3),
    ]


@callback(Output("event-feed-body", "children"), Input("refresh", "n_intervals"))
def _update_feed(_n):
    return event_table(get_recent_events(20))


@callback(Output("severity-chart", "figure"), Input("refresh", "n_intervals"))
def _update_sev(_n):
    df = get_severity_distribution()
    if df.empty:
        return go.Figure().update_layout(
            template="cyborg", height=200,
            annotations=[{"text": "keine Daten", "showarrow": False,
                          "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5}],
        )
    colors = [severity_color(int(s)) for s in df["sev"]]
    fig = go.Figure(go.Bar(
        x=df["sev"].astype(str), y=df["count"],
        marker_color=colors, text=df["count"], textposition="outside",
    ))
    fig.update_layout(
        template="cyborg", height=200,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title="Severity", yaxis_title="Anzahl",
        showlegend=False,
    )
    return fig


@callback(Output("top-hosts-chart", "figure"), Input("refresh", "n_intervals"))
def _update_top(_n):
    df = get_top_hosts(8)
    if df.empty:
        return go.Figure().update_layout(
            template="cyborg", height=200,
            annotations=[{"text": "keine Daten", "showarrow": False,
                          "xref": "paper", "yref": "paper", "x": 0.5, "y": 0.5}],
        )
    df["label"] = df["vendor"].fillna("Unbekannt") + " · " + df["mac"].str[:8]
    df = df.sort_values("event_count")
    fig = go.Figure(go.Bar(
        x=df["event_count"], y=df["label"], orientation="h",
        marker_color="#17a2b8", text=df["event_count"], textposition="outside",
    ))
    fig.update_layout(
        template="cyborg", height=200,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis_title="Events", showlegend=False,
    )
    return fig


@callback(Output("timeline-chart", "figure"), Input("refresh", "n_intervals"))
def _update_timeline(_n):
    try:
        df = get_event_timeline(24)
        if df.empty:
            return go.Figure().update_layout(
                template="cyborg", height=280,
                annotations=[{"text": "keine Events in den letzten 24 h",
                              "showarrow": False,
                              "xref": "paper", "yref": "paper",
                              "x": 0.5, "y": 0.5,
                              "font": {"color": "#888"}}],
            )

        fig = px.bar(
            df, x="hour", y="count", color="detector",
            template="cyborg",
            labels={"hour": "Stunde", "count": "Events",
                    "detector": "Detektor"},
        )
        fig.update_layout(
            height=340,
            margin=dict(l=60, r=30, t=30, b=90),
            legend=dict(
                orientation="h",
                yanchor="top", y=-0.25,
                xanchor="left",  x=0,
                font=dict(color="#e0e0e0", size=11),
                bgcolor="rgba(0,0,0,0)",
            ),
            bargap=0.35,
            xaxis=dict(
                tickformat="%d.%m. %H:%M",
                tickangle=-30,
                showgrid=False,
                tickfont=dict(color="#e0e0e0", size=10),
                dtick=3600000,
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor="#2a2a2a",
                zeroline=True,
                zerolinecolor="#444",
                rangemode="tozero",
                tick0=0,
                dtick=2,
                tickfont=dict(color="#e0e0e0", size=10),
                title=dict(text="Events",
                           font=dict(color="#888", size=10)),
            ),
            # ← DAS ist der entscheidende Fix:
            plot_bgcolor="#0d0d0d",
            paper_bgcolor="#0d0d0d",
            font=dict(color="#e0e0e0"),
        )
        fig.update_traces(
            hovertemplate="<b>%{x|%d.%m. %H:%M}</b><br>"
                          "%{y} Events<extra></extra>",
        )
        return fig
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return go.Figure().update_layout(
            template="cyborg", height=280,
            annotations=[{
                "text": f"Fehler: {type(e).__name__}: {e}<br>"
                        f"<span style='font-size:10px'>{tb[-200:]}</span>",
                "showarrow": False,
                "xref": "paper", "yref": "paper",
                "x": 0.5, "y": 0.5,
                "font": {"size": 11, "color": "#ff6b6b"},
            }],
        )