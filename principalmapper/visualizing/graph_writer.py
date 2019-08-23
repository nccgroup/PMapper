"""Code to write Graph data to various output formats."""

import pydot

from principalmapper.common.graphs import Graph
from principalmapper.querying.presets.privesc import can_privesc


def handle_request(graph: Graph, path: str, format: str) -> None:
    """Meat of the graph_writer.py module, writes graph data in a given file-format to the given path."""
    # Load graph data into pydot
    pydg = pydot.Dot(
        graph_type='digraph',
        graph_name='Principal Mapper Visualization: {}'.format(graph.metadata['account_id']),
        overlap='scale',
        layout='neato',
        concentrate='true',
        splines='true'
    )
    pyd_nd = {}

    for node in graph.nodes:
        if node.is_admin:
            color = '#BFEFFF'
        elif can_privesc(graph, node)[0]:
            color = '#FADBD8'
        else:
            color = 'white'

        pyd_nd[node] = pydot.Node(node.searchable_name(), style='filled', fillcolor=color, shape='box')
        pydg.add_node(pyd_nd[node])

    for edge in graph.edges:
        if not edge.source.is_admin:
            pydg.add_edge(pydot.Edge(pyd_nd[edge.source], pyd_nd[edge.destination]))

    # and draw
    pydg.write(path, format=format)
