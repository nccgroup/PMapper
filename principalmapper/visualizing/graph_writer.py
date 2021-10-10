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
from typing import List, Optional

from principalmapper.common import Graph, Node, Edge
from principalmapper.querying.presets.privesc import can_privesc
from principalmapper.visualizing import graphml_writer, graphviz_writer


def handle_request(graph: Graph, path: str, file_format: str, with_services: Optional[bool] = False) -> None:
    """Meat of the graph_writer.py module, writes graph data in a given file-format to the given path."""

    # adding extra branch to handle new GraphML format
    if file_format == 'graphml':
        return graphml_writer.write_standard_graphml(graph, path, with_services)

    elif file_format in ('svg', 'png', 'dot'):
        return graphviz_writer.write_standard_graphviz(graph, path, file_format, with_services)

    else:
        raise ValueError('Unexpected value for parameter `file_format`')


def draw_privesc_paths(graph: Graph, path: str, file_format: str) -> None:
    """Draws a graph using Graphviz (dot) with a specific set of nodes and edges to highlight admins and privilege
    escalation paths."""

    # adding extra branch to handle new GraphML format
    if file_format == 'graphml':
        return graphml_writer.write_privesc_graphml(graph, path)

    elif file_format in ('svg', 'png', 'dot'):
        return graphviz_writer.write_privesc_graphviz(graph, path, file_format)

    else:
        raise ValueError('Unexpected value for parameter `file_format`')

