"""Code to identify if a principal in an AWS account can use access to IAM to access other principals."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface


class IAMEdgeChecker(EdgeChecker):
    """Goes through the IAM service to locate potential edges between nodes."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""
        result = []
        for node_source in nodes:
            for node_destination in nodes:
                # skip self-access checks
                if node_source == node_destination:
                    continue

                # check if source is an admin, if so it can access destination but this is not tracked via an Edge
                if node_source.is_admin:
                    continue

                # TODO: check if source can change destination's creds (access keys/password) if destination is a user
                if ':role/' in node_destination.arn:
                    pass

                # TODO: check if source can change destination's trust policy if destination is a role
                if ':user/' in node_destination.arn:
                    pass

        return result