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
import logging
import os
from typing import List, Optional

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult, has_matching_statement
from principalmapper.util import arns


logger = logging.getLogger(__name__)


class STSEdgeChecker(EdgeChecker):
    """Class for identifying if STS can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges. If the session object is None, performs checks in offline-mode"""

        result = generate_edges_locally(nodes, scps)
        logger.info('Generating Edges based on STS')

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """

    result = []
    for node_destination in nodes:
        if ':role/' not in node_destination.arn:
            continue  # skip non-roles

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin, if so it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # Check against resource policy
            sim_result = resource_policy_authorization(
                node_source,
                arns.get_account_id(node_source.arn),
                node_destination.trust_policy,
                'sts:AssumeRole',
                node_destination.arn,
                {},
            )

            if sim_result == ResourcePolicyEvalResult.DENY_MATCH:
                continue  # Node was explicitly denied from assuming the role

            if sim_result == ResourcePolicyEvalResult.NO_MATCH:
                continue  # Resource policy must match for sts:AssumeRole, even in same-account scenarios

            assume_auth, need_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source, 'sts:AssumeRole', node_destination.arn, {}, service_control_policy_groups=scps
            )
            policy_denies = has_matching_statement(
                node_source,
                'Deny',
                'sts:AssumeRole',
                node_destination.arn,
                {},
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
            )

            if assume_auth:
                if need_mfa:
                    reason = '(requires MFA) can access via sts:AssumeRole'
                else:
                    reason = 'can access via sts:AssumeRole'
                new_edge = Edge(
                    node_source,
                    node_destination,
                    reason,
                    'AssumeRole'
                )
                result.append(new_edge)
            elif not (policy_denies_mfa and policy_denies) and sim_result == ResourcePolicyEvalResult.NODE_MATCH:
                # testing same-account scenario, so NODE_MATCH will override a lack of an allow from iam policy
                new_edge = Edge(
                    node_source,
                    node_destination,
                    'can access via sts:AssumeRole',
                    'AssumeRole'
                )
                result.append(new_edge)

    return result
