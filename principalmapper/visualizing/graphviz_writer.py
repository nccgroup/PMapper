#  Copyright (c) NCC Group and Erik Steringer 2020. This file is part of Principal Mapper.
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

from typing import Dict, List, Optional

import pydot

from principalmapper.common import Graph, Node, Edge
from principalmapper.querying.presets.privesc import can_privesc
from principalmapper.querying.presets.serviceaccess import compose_service_access_map


def write_standard_graphviz(graph: Graph, filepath: str, file_format: str, with_services: Optional[bool] = False) -> None:
    """The function to generate the standard visualization with a Graphviz-generated file: this is all the nodes
    with the admins/privesc highlights in blue/red respectively."""

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

    # Draw standard nodes and edges: users/roles
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

    # draw service nodes and edges
    if with_services:
        sam = compose_service_access_map(graph)
        for service in sam.keys():
            pyd_nd[service] = pydot.Node(service, style='filled', fillcolor='#DDFFDD')
            pydg.add_node(pyd_nd[service])

        for service, node_list in sam.items():
            for node in node_list:
                pydg.add_edge(pydot.Edge(pyd_nd[service], pyd_nd[node]))

    # and draw
    pydg.write(filepath, format=file_format)


def write_privesc_graphviz(graph: Graph, filepath: str, file_format: str) -> None:
    """The function to generate the privesc-only visualization with a Graphviz-generated file: this is only the
    nodes that are admins/privesc with blue/red highlights."""

    pydg = pydot.Dot(
        graph_type='digraph',
        overlap='scale',
        layout='dot',
        splines='ortho',
        rankdir='LR',
        forcelabels='true'
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

                edge_to_add = pydot.Edge(node.searchable_name(), edge_list[0].destination.searchable_name(),
                                         xlabel=edge_list[0].short_reason)
                pydg.add_edge(edge_to_add)

        pydg.add_subgraph(s)

    # and draw
    pydg.write(filepath, format=file_format)


def generate_graphviz(graph: Graph, nodes: List[Node], edges: List[Edge], filepath: str, file_format: str) -> None:
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
    pydg.write(filepath, format=file_format)
