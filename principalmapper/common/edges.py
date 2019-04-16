"""Python code for implementing the edges of a graph"""

from .nodes import Node


class Edge(object):
    """The basic Edge object"""

    def __init__(self, source: Node = None, destination: Node = None):
        """Constructor"""
        if source is None:
            raise ValueError('Edges must have a source Node object')
        if destination is None:
            raise ValueError('Edges must have a destination Node object')

        self.source = source
        self.destination = destination
