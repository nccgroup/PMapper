"""Python code for implementing the edges of a graph"""

#  Copyright NCC Group (c) 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Foobar.  If not, see <https://www.gnu.org/licenses/>.

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
