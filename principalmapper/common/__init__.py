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


"""Module defining classes and functions used commonly across Principal Mapper. Importing this package currently gives
the Node, Edge, Graph, Group, and Policy classes, i.e. you can use `from principalmapper.common import Graph`."""

from principalmapper.common.nodes import Node
from principalmapper.common.edges import Edge
from principalmapper.common.graphs import Graph
from principalmapper.common.groups import Group
from principalmapper.common.policies import Policy

# Put submodules into __all__ for neater interface of principalmapper.common
__all__ = ['Node', 'Edge', 'Graph', 'Group', 'Policy']
