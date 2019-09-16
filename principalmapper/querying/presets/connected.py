"""Query preset for testing if a principal is connected to another, or listing what a principal is connected to."""

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

import io
import os
from typing import List

from principalmapper.common import Edge, Node, Graph
from principalmapper.querying.query_utils import get_search_list


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False, output: io.StringIO = os.devnull,
                        debug: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and writes the result to output."""
    source_target = tokens[2]
    dest_target = tokens[3]

    source_nodes = []
    dest_nodes = []
    if source_target == '*':
        source_nodes.extend(graph.nodes)
    else:
        source_nodes.append(graph.get_node_by_searchable_name(source_target))

    if dest_target == '*':
        dest_nodes.extend(graph.nodes)
    else:
        dest_nodes.append(graph.get_node_by_searchable_name(dest_target))

    write_connected_results(graph, source_nodes, dest_nodes, skip_admins, output, debug)


def write_connected_results(graph: Graph, source_nodes: List[Node], dest_nodes: List[Node], skip_admins: bool = False,
                            output: io.StringIO = os.devnull, debug: bool = False) -> None:
    """Handles a `connected` query and writes the results to output"""
    for snode in source_nodes:
        if skip_admins and snode.is_admin:
            continue

        for dnode in dest_nodes:
            connection_result, path = is_connected(graph, snode, dnode, debug)
            if connection_result:
                # print the data
                output.write('{} is able to access {}:\n'.format(snode.searchable_name(), dnode.searchable_name()))
                for edge in path:
                    output.write('   {}\n'.format(edge.describe_edge()))


def is_connected(graph: Graph, source_node: Node, dest_node: Node, debug: bool = False) -> (bool, List[Edge]):
    """Method for determining if a source node can reach a destination node through edges. The return value is a
    bool, List[Edge] tuple indicating if there's a connection and the path the source node would need to take.
    """
    edge_lists = get_search_list(graph, source_node)
    for edge_list in edge_lists:
        final_node = edge_list[-1].destination
        if final_node == dest_node:
            return True, edge_list

    return False, None
