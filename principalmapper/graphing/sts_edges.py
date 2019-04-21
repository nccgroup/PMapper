"""Code to identify if a principal in an AWS account can use access to STS to access other principals."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface


class STSEdgeChecker(EdgeChecker):
    """Goes through the IAM service to locate potential edges between nodes."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges"""
        result = []
        iamclient = self.session.create_client('iam')
        for node_source in nodes:
            for node_destination in nodes:
                # skip self-access checks
                if node_source == node_destination:
                    continue

                # check if source is an admin, if so it can access destination but this is not tracked via an Edge
                if node_source.is_admin:
                    continue

                # check if source can call sts:AssumeRole to access the destination if destination is a role
                if ':role/' in node_destination.arn:
                    if query_interface.is_authorized_for(iamclient, node_source, 'sts:AssumeRole', node_destination.arn,
                                                         {}, True, debug):
                        policy_allows = query_interface.resource_policy_has_matching_statement(node_source,
                                                                                               node_destination.trust_policy,
                                                                                               'Allow',
                                                                                               'sts:AssumeRole',
                                                                                               node_destination.arn,
                                                                                               {},
                                                                                               debug)
                        policy_denies = query_interface.resource_policy_has_matching_statement(node_source,
                                                                                               node_destination.trust_policy,
                                                                                               'Deny',
                                                                                               'sts:AssumeRole',
                                                                                               node_destination.arn,
                                                                                               {},
                                                                                               debug)
                        if policy_allows and not policy_denies:
                            new_edge = Edge(
                                node_source,
                                node_destination,
                                'can access via sts:AssumeRole'
                            )
                            output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                            result.append(new_edge)

        return result
