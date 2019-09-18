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

from principalmapper.common import Graph
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
