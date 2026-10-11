"""Wiederverwendbarer Seiten-Header."""
from dash import html


def page_header(title: str, subtitle: str = "") -> html.Div:
    children = [html.H2(title, className="mb-1 text-white")]
    if subtitle:
        children.append(html.P(subtitle, className="text-muted mb-4"))
    return html.Div(children)