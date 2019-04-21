"""Holds the base object EdgeChecker to be implemented and used in identifying edges"""

import io
import os
from typing import List

import botocore.session

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node


class EdgeChecker(object):
    """Base class for all edge-identifying classes."""

    def __init__(self, session: botocore.session.Session):
        self.session = session

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Expect subclasses to override. Given a list of nodes, the EdgeChecker should be able to use its session
        object in order to make clients and call the AWS API to resolve information about the account. Then,
        with this information, it should return a list of edges between the passed nodes.
        """
        raise NotImplementedError('The return_edges method should not be called from EdgeChecker, but rather from an '
                                  'object that subclasses EdgeChecker')
