"""Python module containing the basic Edge class, as well as any utility functions (currently none)."""


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

from principalmapper.util import arns


class Edge(object):
    """The Edge object: contains a source and destination Node object, as well as a string that explains how
    the source Node is able to access the destination Node.
    """

    def __init__(self, source, destination, reason: str, short_reason: str):
        """Constructor"""
        if source is None:
            raise ValueError('Edges must have a source Node object')
        if destination is None:
            raise ValueError('Edges must have a destination Node object')
        if reason is None:
            raise ValueError('Edges must be constructed with a reason parameter (str)')
        if short_reason is None:
            raise ValueError('Edges must be constructed with a short_reason parameter (str)')

        self.source = source
        self.destination = destination
        self.reason = reason
        self.short_reason = short_reason

    def describe_edge(self) -> str:
        """Returns a human-readable string explaining the edge"""
        return "{} {} {}".format(
            self.source.searchable_name(),
            self.reason,
            self.destination.searchable_name()
        )

    def to_dictionary(self) -> dict:
        """Returns a dictionary representation of this object for storage"""
        return {
            'source': self.source.arn,
            'destination': self.destination.arn,
            'reason': self.reason,
            'short_reason': self.short_reason
        }
