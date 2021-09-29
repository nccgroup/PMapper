"""Code to identify if a principal in an AWS account can use access to IAM to access other principals."""


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


logger = logging.getLogger(__name__)


class IAMEdgeChecker(EdgeChecker):
    """Class for identifying if IAM can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on IAM')
        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}\n".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """
    result = []

    for node_source in nodes:
        for node_destination in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin, if so it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            if ':user/' in node_destination.arn:
                # Change the user's access keys
                access_keys_mfa = False

                create_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:CreateAccessKey',
                    node_destination.arn,
                    {},
                    service_control_policy_groups=scps
                )

                if mfa_res:
                    access_keys_mfa = True

                if node_destination.access_keys == 2:
                    # can have a max of two access keys, need to delete before making a new one
                    auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:DeleteAccessKey',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                    if not auth_res:
                        create_auth_res = False  # can't delete target access key, can't generate a new one
                    if mfa_res:
                        access_keys_mfa = True

                if create_auth_res:
                    reason = 'can create access keys to authenticate as'
                    if access_keys_mfa:
                        reason = '(MFA required) ' + reason

                    result.append(
                        Edge(
                            node_source, node_destination, reason, 'IAM'
                        )
                    )

                # Change the user's password
                if node_destination.active_password:
                    pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:UpdateLoginProfile',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                else:
                    pass_auth_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'iam:CreateLoginProfile',
                        node_destination.arn,
                        {},
                        service_control_policy_groups=scps
                    )
                if pass_auth_res:
                    reason = 'can set the password to authenticate as'
                    if mfa_res:
                        reason = '(MFA required) ' + reason
                    result.append(Edge(node_source, node_destination, reason, 'IAM'))

            if ':role/' in node_destination.arn:
                # Change the role's trust doc
                update_role_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:UpdateAssumeRolePolicy',
                    node_destination.arn,
                    {},
                    service_control_policy_groups=scps
                )
                if update_role_res:
                    reason = 'can update the trust document to access'
                    if mfa_res:
                        reason = '(MFA required) ' + reason
                    result.append(Edge(node_source, node_destination, reason, 'IAM'))

    return result
