"""Utility functions that help with querying"""

from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.graphs import Graph
from principalmapper.common.nodes import Node


def get_search_list(graph: Graph, node: Node) -> List[List[Edge]]:
    """Returns a list of edge lists. Each edge list represents a path to a new unique node that's accessible from the
    initial node (passed as a param). This is a breadth-first search of nodes from a source node in a graph.
    """
    result = []
    explored_nodes = []

    # run through initial edges
    for edge in get_edges_with_node_source(graph, node, explored_nodes):
        result.append([edge])
    explored_nodes.append(node)

    # dig through result list
    index = 0
    while index < len(result):
        current_node = result[index][-1].destination
        for edge in get_edges_with_node_source(graph, current_node, explored_nodes):
            result.append(result[index][:] + [edge])
        explored_nodes.append(current_node)
        index += 1

    return result


def get_edges_with_node_source(graph: Graph, node: Node, ignored_nodes: List[Node]) -> List[Edge]:
    """Returns a list of nodes that are the destination of edges from the given graph where source of the edge is the
    passed node.
    """
    result = []
    for edge in graph.edges:
        if edge.source == node and edge.destination not in ignored_nodes:
            result.append(edge)
    return result


def is_connected(graph: Graph, source: Node, destination: Node) -> bool:
    """helper function to express if source and node are connected"""
    if source.is_admin:
        return True

    for node_list in get_search_list(graph, source):
        if node_list[-1].destination == destination:
            return True

    return False
