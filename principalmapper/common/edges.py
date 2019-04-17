"""Python code for implementing the edges of a graph"""

from principalmapper.common.nodes import Node
from principalmapper.util import arns


class Edge(object):
    """The basic Edge object"""

    def __init__(self, source: Node, destination: Node, reason: str):
        """Constructor"""
        if source is None:
            raise ValueError('Edges must have a source Node object')
        if destination is None:
            raise ValueError('Edges must have a destination Node object')
        if reason is None:
            raise ValueError('Edges must be constructed with a string reason parameter')

        self.source = source
        self.destination = destination
        self.reason = reason

    def describe_edge(self):
        """Returns a human-readable string explaining the edge"""
        return "{} {} {}".format(
            arns.get_resource(self.source.arn),
            self.reason,
            arns.get_resource(self.destination.arn)
        )

    def to_dictionary(self):
        """Returns a dictionary representation of this object for storage"""
        return {
            'source': self.source.arn,
            'destination': self.destination.arn,
            'reason': self.reason
        }
