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

import io
import os
from typing import List, Dict

from principalmapper.common import Node, Graph
from principalmapper.querying.presets.connected import is_connected


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and prints the result."""

    tag_name_target = tokens[2]
    clusters = generate_clusters(graph, tag_name_target)

    print('# Clusters identified on key {}'.format(tag_name_target))
    for k in clusters.keys():
        if k is None:
            continue
        print('{}:'.format(k))
        for n in clusters[k]:
            print('   {}'.format(n.searchable_name()))

    print()
    print('# Boundaries crossed on key {}'.format(tag_name_target))
    for source in clusters.keys():
        if source is None:
            continue

        for destination in clusters.keys():
            if destination is None or source == destination:
                continue

            for src_node in clusters[source]:
                for dst_node in clusters[destination]:
                    connected, path = is_connected(graph, src_node, dst_node)
                    if connected:
                        print('{} can cross boundaries and access {}'.format(
                            src_node.searchable_name(), dst_node.searchable_name()
                        ))
                        for edge in path:
                            print('   {}'.format(edge.describe_edge()))


def generate_clusters(graph: Graph, tag_name_target: str) -> Dict[str, List[Node]]:
    """Given a graph, and a key of a tag to work from, group up all the nodes using those tags."""

    result = {}
    for node in graph.nodes:
        if tag_name_target in node.tags:
            value = node.tags[tag_name_target]
        else:
            value = None

        if value not in result:
            result[value] = [node]
        else:
            result[value].append(node)

    return result
