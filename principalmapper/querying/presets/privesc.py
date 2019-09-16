"""Query preset for testing if a principal can escalate privileges. This is intentionally broken up into multiple
methods to make it usable programmatically. Call can_privesc with a Graph and Node to get results that don't require
parsing text output."""

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
from principalmapper.util.debug_print import dprint


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False, output: io.StringIO = os.devnull,
                        debug: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and writes the result to output."""
    # Get the nodes we're determining can privesc or not
    target = tokens[2]
    nodes = []
    if target == '*':
        nodes.extend(graph.nodes)
    else:
        nodes.append(graph.get_node_by_searchable_name(target))
    write_privesc_results(graph, nodes, skip_admins, output, debug)


def write_privesc_results(graph: Graph, nodes: List[Node], skip_admins: bool = False, output: io.StringIO = os.devnull,
                          debug: bool = False) -> None:
    """Handles a privesc query and writes the result to output."""
    for node in nodes:
        dprint(debug, 'Looking at principal {}'.format(node.searchable_name()))
        if skip_admins and node.is_admin:
            continue  # skip admins

        if node.is_admin:
            output.write('{} is an administrative principal\n'.format(node.searchable_name()))
            continue

        privesc, edge_list = can_privesc(graph, node, debug)
        if privesc:
            end_of_list = edge_list[-1].destination
            # the node can access this admin node through the current edge list, print this info out
            output.write('{} can escalate privileges by accessing the administrative principal {}:\n'.format(
                node.searchable_name(), end_of_list.searchable_name()))
            for edge in edge_list:
                output.write('   {}\n'.format(edge.describe_edge()))


def can_privesc(graph: Graph, node: Node, debug: bool = False) -> (bool, List[Edge]):
    """Method for determining if a given Node in a Graph can escalate privileges.

    Returns a bool, List[Edge] tuple. The bool indicates if there is a privesc risk, and the List[Edge] component
    describes the path of edges the node would have to take to gain access to the admin node.
    """
    edge_lists = get_search_list(graph, node)
    searched_nodes = []
    for edge_list in edge_lists:
        # check if the node at the end of the list has been looked at yet, skip if so
        end_of_list = edge_list[-1].destination
        if end_of_list in searched_nodes:
            continue

        # add end of list to the searched nodes and do the privesc check
        searched_nodes.append(end_of_list)
        if end_of_list.is_admin:
            return True, edge_list
    return False, None
