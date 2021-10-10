"""Holds the base object EdgeChecker to be implemented and used in other classes that identify edges."""


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

import io
import os
from typing import List, Optional

import botocore.session

from principalmapper.common import Edge, Node


class EdgeChecker(object):
    """Base class for all edge-identifying classes."""

    def __init__(self, session: botocore.session.Session):
        self.session = session

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Subclasses shall override this method. Given a list of nodes, the EdgeChecker should be able to use its session
        object in order to make clients and call the AWS API to resolve information about the account. Then,
        with this information, it should return a list of edges between the passed nodes.

        The region allow/deny lists are mutually-exclusive (i.e. at least one of which has the value None) lists of
        allowed/denied regions to pull data from.
        """
        raise NotImplementedError('The return_edges method should not be called from EdgeChecker, but rather from an '
                                  'object that subclasses EdgeChecker')
