"""Code to identify if a principal in an AWS account can use access to STS to access other principals."""

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
from typing import List

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult, has_matching_statement
from principalmapper.util import arns


class STSEdgeChecker(EdgeChecker):
    """Class for identifying if STS can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], output: io.StringIO = os.devnull, debug: bool = False) -> List[Edge]:
        """Fulfills expected method return_edges. If the session object is None, performs checks in offline-mode"""
        result = []
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

                    assume_auth, need_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source, 'sts:AssumeRole', node_destination.arn, {}, debug
                    )
                    policy_denies = has_matching_statement(
                        node_source,
                        'Deny',
                        'sts:AssumeRole',
                        node_destination.arn,
                        {},
                        debug
                    )
                    policy_denies_mfa = has_matching_statement(
                        node_source,
                        'Deny',
                        'sts:AssumeRole',
                        node_destination.arn,
                        {
                            'aws:MultiFactorAuthAge': '1',
                            'aws:MultiFactorAuthPresent': 'true'
                        },
                        debug
                    )

                    if assume_auth:
                        if need_mfa:
                            reason = '(requires MFA) can access via sts:AssumeRole'
                        else:
                            reason = 'can access via sts:AssumeRole'
                        new_edge = Edge(
                            node_source,
                            node_destination,
                            reason
                        )
                        output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                        result.append(new_edge)
                    elif not (policy_denies_mfa and policy_denies) and sim_result == ResourcePolicyEvalResult.NODE_MATCH:
                        # testing same-account scenario, so NODE_MATCH will override a lack of an allow from iam policy
                        new_edge = Edge(
                            node_source,
                            node_destination,
                            'can access via sts:AssumeRole'
                        )
                        output.write('Found new edge: {}\n'.format(new_edge.describe_edge()))
                        result.append(new_edge)

        return result
