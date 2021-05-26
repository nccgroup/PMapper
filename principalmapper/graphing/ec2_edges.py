"""Code to identify if a principal in an AWS account can use access to EC2 to access other principals."""


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


class EC2EdgeChecker(EdgeChecker):
    """Class for identifying if EC2 can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on EC2.')
        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """

    result = []
    for node_destination in nodes:
        # check if destination is a user, skip if so
        if ':role/' not in node_destination.arn:
            continue

        # check that the destination role can be assumed by EC2
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

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # check if source can pass the destination role
            mfa_needed = False
            condition_keys = {'iam:PassedToService': 'ec2.amazonaws.com'}
            pass_role_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                condition_keys,
                service_control_policy_groups=scps
            )
            if not pass_role_auth:
                continue  # source can't pass the role to use it

            # check if destination has an instance profile, if not: check if source can create it
            if node_destination.instance_profile is None:
                create_ip_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source, 'iam:CreateInstanceProfile', '*', {}, service_control_policy_groups=scps)
                if not create_ip_auth:
                    continue  # node_source can't make the instance profile
                if mfa_res:
                    mfa_needed = True

                create_ip_auth, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source, 'iam:AddRoleToInstanceProfile', node_destination.arn, {}, service_control_policy_groups=scps)
                if not create_ip_auth:
                    continue  # node_source can't attach a new instance profile to node_destination
                if mfa_res:
                    mfa_needed = True

            # check if source can run an instance with the instance profile condition, add edge if so and continue
            if node_destination.instance_profile is not None and len(node_destination.instance_profile) > 0:
                iprofile = node_destination.instance_profile[0]
                condition_keys = {'ec2:InstanceProfile': iprofile}
            else:
                iprofile = '*'
                condition_keys = {}

            create_instance_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ec2:RunInstances',
                '*',
                condition_keys,
                service_control_policy_groups=scps
            )

            if mfa_res:
                mfa_needed = True

            if create_instance_res:
                if iprofile != '*':
                    reason = 'can use EC2 to run an instance with an existing instance profile to access'
                else:
                    reason = 'can use EC2 to run an instance with a newly created instance profile to access'
                if mfa_needed:
                    reason = '(MFA required) ' + reason

                new_edge = Edge(
                    node_source,
                    node_destination,
                    reason,
                    'EC2'
                )
                result.append(new_edge)

            # check if source can run an instance without an instance profile then add the profile, add edge if so
            create_instance_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'ec2:RunInstances',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if mfa_res:
                mfa_needed = True

            if create_instance_res:
                attach_ip_res, mfa_res = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'ec2:AssociateIamInstanceProfile',
                    '*',
                    condition_keys,
                    service_control_policy_groups=scps
                )

                if iprofile != '*':
                    reason = 'can use EC2 to run an instance and then associate an existing instance profile to ' \
                             'access'
                else:
                    reason = 'can use EC2 to run an instance and then attach a newly created instance profile to ' \
                             'access'

                if mfa_res or mfa_needed:
                    reason = '(MFA required) ' + reason

                if attach_ip_res:
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason,
                        'EC2'
                    )
                    result.append(new_edge)

    return result
