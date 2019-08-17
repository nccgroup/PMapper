"""Class representation of a query result."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node


class QueryResult(object):
    """Query result object returned by querying methods."""
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
