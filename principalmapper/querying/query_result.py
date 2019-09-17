"""Class representation of a query result."""


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

from principalmapper.common import Edge, Node


class QueryResult(object):
    """Query result object returned by querying methods. The allowed field specifies if the passed Node is authorized
    to make the API call. The edge_list field, if not an empty list, specifies which edges the Node must traverse
    to make the API call.
    """
    def __init__(self, allowed: bool, edge_list: List[Edge], node: Node):
        self.allowed = allowed
        self.edge_list = edge_list
        self.node = node

    def write_result(self, action_param: str, resource_param: str, output: io.StringIO = os.devnull):
        """Writes information above the QueryResult object to the given IO interface."""
        if self.allowed:
            if len(self.edge_list) == 0:
                # node itself is auth'd
                output.write('{} is authorized to call action {} for resource {}\n'.format(
                    self.node.searchable_name(), action_param, resource_param))

            else:
                # node is auth'd through other nodes
                output.write('{} is authorized to call action {} for resource {} via {}\n'.format(
                    self.node.searchable_name(), action_param, resource_param,
                    self.edge_list[-1].destination.searchable_name()
                ))

                # print the path the node has to take
                for edge in self.edge_list:
                    output.write('   {}\n'.format(edge.describe_edge()))

                # print that the end-edge is authorized to make the call
                output.write('   {} is authorized to call action {} for resource {}\n'.format(
                    self.edge_list[-1].destination.searchable_name(),
                    action_param,
                    resource_param
                ))
