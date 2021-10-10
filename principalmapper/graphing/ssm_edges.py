"""Code to identify if a principal in an AWS account can use access to SSM to access other principals."""

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
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns


logger = logging.getLogger(__name__)


class SSMEdgeChecker(EdgeChecker):
    """Class for identifying if SSM can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""

        logger.info('Generating Edges based on SSM')
        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """

    result = []

    for node_destination in nodes:
        # check if destination is a role with an instance profile
        if ':role/' not in node_destination.arn or node_destination.instance_profile is None:
            continue

        # check if the destination can be assumed by EC2
        sim_result = resource_policy_authorization(
            'ec2.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {},
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # EC2 wasn't auth'd to assume the role

        # at this point, we make an assumption that some instance is operating with the given instance profile
        # we assume if the role can call ssmmessages:CreateControlChannel, anyone with ssm perms can access it
        if not query_interface.local_check_authorization(node_destination, 'ssmmessages:CreateControlChannel', '*', {}):
            continue

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin, if so it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # so if source can call ssm:SendCommand or ssm:StartSession, it's an edge
            cmd_auth_res, mfa_res_1 = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ssm:SendCommand',
                '*',
                {},
            )

            if cmd_auth_res:
                reason = 'can call ssm:SendCommand to access an EC2 instance with access to'
                if mfa_res_1:
                    reason = '(Requires MFA) ' + reason
                result.append(Edge(node_source, node_destination, reason, 'SSM'))

            sesh_auth_res, mfa_res_2 = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ssm:StartSession',
                '*',
                {},
            )

            if sesh_auth_res:
                reason = 'can call ssm:StartSession to access an EC2 instance with access to'
                if mfa_res_2:
                    reason = '(Requires MFA) ' + reason
                result.append(Edge(node_source, node_destination, reason, 'SSM'))

    return result
