# dashboard/pages/overview.py (Ausschnitt)
import dash_cytoscape as cyto
import networkx as nx
from dashboard.data import get_connection

def create_topology_graph():
    # 1. Verbindungen aus der DB abrufen (z.B. aus der 'hosts'-Tabelle)
    # ... (SQL-Abfrage für src_ip, dst_ip, count) ...
    # 2. Einen Graphen mit networkx erstellen
    G = nx.Graph()
    # ... Knoten (Hosts) und Kanten (Verbindungen) hinzufügen ...

    # 3. Den Graphen in Cytoscape-Elemente umwandeln
    cyto_elements = []
    for node in G.nodes(data=True):
        cyto_elements.append({'data': {'id': node[0], 'label': node[0]}})
    for edge in G.edges(data=True):
        cyto_elements.append({'data': {'source': edge[0], 'target': edge[1]}})

    return cyto_elements

# Im Layout:
cyto.Cytoscape(
    id='network-topology',
    elements=create_topology_graph(),
    layout={'name': 'cose'}, # 'cose' ist ein kraftgerichtetes Layout
    style={'width': '100%', 'height': '500px'},
    stylesheet=[ # Farbgebung nach Vendor
        {'selector': 'node', 'style': {'label': 'data(label)'}},
        {'selector': '[label *= "Apple"]', 'style': {'background-color': '#a2d2ff'}},
        # ... weitere Selektoren ...
    ]
)