"""Code to identify if a principal in an AWS account can use access to STS to access other principals."""

import io
import os
from typing import List

from principalmapper.common.edges import Edge
from principalmapper.common.nodes import Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult, has_matching_statement
from principalmapper.util import arns


class STSEdgeChecker(EdgeChecker):
    """Goes through the STS service to locate potential edges between nodes."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges. If the session object is None, performs checks in offline-mode"""
        result = []
        if self.session is not None:
            iamclient = self.session.create_client('iam')
        else:
            iamclient = None
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
                    # Check against resource policy
                    sim_result = resource_policy_authorization(
                        node_source,
                        arns.get_account_id(node_source.arn),
                        node_destination.trust_policy,
                        'sts:AssumeRole',
                        node_destination.arn,
                        {},
                        debug
                    )

                    if sim_result == ResourcePolicyEvalResult.DENY_MATCH:
                        continue  # Node was explicitly denied from assuming the role

                    if sim_result == ResourcePolicyEvalResult.NO_MATCH:
                        continue  # Resource policy must match for sts:AssumeRole, even in same-account scenarios

                    policy_allows = has_matching_statement(node_source, 'Allow', 'sts:AssumeRole',
                                                           node_destination.arn, {}, debug)
                    policy_denies = has_matching_statement(node_source, 'Deny', 'sts:AssumeRole',
                                                           node_destination.arn, {}, debug)
                    if policy_allows and not policy_denies:
                        new_edge = Edge(
                            node_source,
                            node_destination,
                            'can access via sts:AssumeRole'
                        )
                        output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                        result.append(new_edge)
                    elif not policy_denies and sim_result == ResourcePolicyEvalResult.NODE_MATCH:
                        # testing same-account scenario, so NODE_MATCH will override a lack of an allow from iam policy
                        new_edge = Edge(
                            node_source,
                            node_destination,
                            'can access via sts:AssumeRole'
                        )
                        output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                        result.append(new_edge)

        return result
