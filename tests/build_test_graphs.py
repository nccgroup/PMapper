"""Code for building Graph objects for testing purposes"""

import principalmapper
from principalmapper.common.graphs import Graph


def build_empty_graph() -> Graph:
    """Constructs and returns a Graph object with no nodes, edges, policies, or groups"""
    return Graph([], [], [], [], {'account_id': '000000000000', 'pmapper_version': principalmapper.__version__})
