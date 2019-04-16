"""Python code for implementing a graph"""


class Graph(object):
    """The basic Graph object"""

    def __init__(self, nodes: list = None, edges: list = None):
        """Constructor"""
        if nodes is None:
            self.nodes = []
        else:
            self.nodes = nodes
        if edges is None:
            self.edges = []
        else:
            self.edges = edges
