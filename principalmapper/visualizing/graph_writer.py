"""Code to write Graph data to various output formats."""


#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import pydot
from typing import List

from principalmapper.common import Graph, Node, Edge
from principalmapper.querying.presets.privesc import can_privesc


def handle_request(graph: Graph, path: str, file_format: str) -> None:
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
    pydg.write(path, format=file_format)


def draw_privesc_paths(graph: Graph, path: str, file_format: str) -> None:
    """Draws a graph using Graphviz (dot) with a specific set of nodes and edges to highlight admins and privilege
    escalation paths."""
    pydg = pydot.Dot(
        graph_type='digraph',
        overlap='scale',
        layout='dot',
        splines='true',
        rankdir='LR'
    )

    pydot_nodes = {}

    # Need to draw in order of "rank", one new subgraph per-rank, using the edge_list length from the privesc method
    ranked_nodes = {}
    for node in graph.nodes:
        if node.is_admin:
            if 0 not in ranked_nodes:
                ranked_nodes[0] = []
            ranked_nodes[0].append(node)
        else:
            pe, edge_list = can_privesc(graph, node)
            if pe:
                if len(edge_list) not in ranked_nodes:
                    ranked_nodes[len(edge_list)] = []
                ranked_nodes[len(edge_list)].append(node)

    for rank in sorted(ranked_nodes.keys()):
        s = pydot.Subgraph(rank='same')
        for node in ranked_nodes[rank]:
            if node.is_admin:
                # just draw the node and nothing more
                pydot_node = pydot.Node(node.searchable_name(), style='filled', fillcolor='#BFEFFF', shape='box')
                pydot_nodes[node] = pydot_node
                s.add_node(pydot_node)
            else:
                # draw the node + add edge
                pe, edge_list = can_privesc(graph, node)
                pydot_node = pydot.Node(node.searchable_name(), style='filled', fillcolor='#FADBD8', shape='box')
                pydot_nodes[node] = pydot_node
                s.add_node(pydot_node)

                edge_to_add = pydot.Edge(node.searchable_name(), edge_list[0].destination.searchable_name(), label=edge_list[0].short_reason)
                pydg.add_edge(edge_to_add)

        pydg.add_subgraph(s)

    # and draw
    pydg.write(path, format=file_format)


def draw_specific_nodes_and_edges(graph: Graph, nodes: List[Node], edges: List[Edge], path: str, file_format: str) -> None:
    """Draws a graph using Graphviz (dot) with a specific set of nodes and edges."""
    pydg = pydot.Dot(
        graph_type='digraph',
        overlap='scale',
        layout='neato',
        splines='true'
    )
    pyd_nd = {}

    for node in nodes:
        if node.is_admin:
            color = '#BFEFFF'
        elif can_privesc(graph, node)[0]:
            color = '#FADBD8'
        else:
            color = 'white'

        pyd_nd[node] = pydot.Node(node.searchable_name(), style='filled', fillcolor=color, shape='box')
        pydg.add_node(pyd_nd[node])

    for edge in edges:
        if not edge.source.is_admin:
            pydg.add_edge(pydot.Edge(pyd_nd[edge.source], pyd_nd[edge.destination], label=edge.short_reason))

    # and draw
    pydg.write(path, format=file_format)
