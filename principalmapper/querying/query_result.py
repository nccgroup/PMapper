"""Class representation of a query result."""

from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node


class QueryResult(object):
    """Query result object returned by querying methods."""
    def __init__(self, allowed: bool, edge_list: List[Edge], node: Node):
        self.allowed = allowed
        self.edge_list = edge_list
        self.node = node
