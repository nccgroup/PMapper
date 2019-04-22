"""Class representation of a query result."""

from typing import List

from principalmapper.common.nodes import Node


class QueryResult(object):
    """Query result objcet to """
    def __init__(self, allowed: bool, node_list: List[Node]):
        self.allowed = allowed
        self.node_list = node_list
