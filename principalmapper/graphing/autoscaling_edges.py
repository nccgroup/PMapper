"""Code to identify if a principal in an AWS account can use access to EC2 Auto Scaling to access other principals."""


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

import logging
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns, botocore_tools

logger = logging.getLogger(__name__)


class AutoScalingEdgeChecker(EdgeChecker):
    """Class for identifying if EC2 Auto Scaling can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on EC2 Auto Scaling.')

        if client_args_map is None:
            asargs = {}
        else:
            asargs = client_args_map.get('autoscaling', {})

        # Gather projects information for each region
        autoscaling_clients = []
        if self.session is not None:
            as_regions = botocore_tools.get_regions_to_search(self.session, 'autoscaling', region_allow_list, region_deny_list)
            for region in as_regions:
                autoscaling_clients.append(self.session.create_client('autoscaling', region_name=region, **asargs))

        launch_configs = []
        for as_client in autoscaling_clients:
            logger.debug('Looking at region {}'.format(as_client.meta.region_name))
            try:
                lc_paginator = as_client.get_paginator('describe_launch_configurations')
                for page in lc_paginator.paginate():
                    if 'LaunchConfigurations' in page:
                        for launch_config in page['LaunchConfigurations']:
                            if 'IamInstanceProfile' in launch_config and launch_config['IamInstanceProfile']:
                                launch_configs.append({
                                    'lc_arn': launch_config['LaunchConfigurationARN'],
                                    'lc_iip': launch_config['IamInstanceProfile']
                                })

            except ClientError as ex:
                logger.warning('Unable to search region {} for launch configs. The region may be disabled, or the error may '
                               'be caused by an authorization issue. Continuing.'.format(as_client.meta.region_name))
                logger.debug('Exception details: {}'.format(ex))

        result = generate_edges_locally(nodes, scps, launch_configs)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None, launch_configs: Optional[List[dict]] = None) -> List[Edge]:
    """Generates and returns Edge objects related to EC2 AutoScaling.

    It is possible to use this method if you are operating offline (infra-as-code). The `launch_configs` param
    should be a list of dictionary objects with the following expected structure:

    ~~~
    {
        'lc_arn': <Launch Configurations ARN>,
        'lc_iip': <IAM Instance Profile>
    }
    ~~~

    All elements are required, but if there is no instance profile then set the field to None.
    """

    result = []

    # iterate through nodes, setting up the map as well as identifying if the service role is available
    role_lc_map = {}
    service_role_available = False
    for node in nodes:
        # this should catch the normal service role + custom ones with the suffix
        if ':role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling' in node.arn:
            service_role_available = True

        if node.instance_profile is not None:
            for launch_config in launch_configs:
                if launch_config['lc_iip'] in node.instance_profile:
                    if node in role_lc_map:
                        role_lc_map[node].append(launch_config['lc_arn'])
                    else:
                        role_lc_map[node] = [launch_config['lc_arn']]

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

            csr_mfa = False  # stash for later ref
            if not service_role_available:
                create_service_role_auth, csr_mfa = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'iam:CreateServiceLinkedRole',
                    '*',
                    {
                        'iam:AWSServiceName': 'autoscaling.amazonaws.com'
                    },
                    service_control_policy_groups=scps
                )
                if not create_service_role_auth:
                    continue  # service role can't be used if it doesn't exist or be created

            create_auto_scaling_group_auth, casg_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'autoscaling:CreateAutoScalingGroup',
                '*',
                {},
                service_control_policy_groups=scps
            )
            if not create_auto_scaling_group_auth:
                continue  # can't create an auto-scaling group -> move along

            if node_destination in role_lc_map:
                if service_role_available:
                    reason = 'can use the EC2 Auto Scaling service role and an existing Launch Configuration to access'
                else:
                    reason = 'can create the EC2 Auto Scaling service role and an existing Launch Configuration to access'

                if csr_mfa or casg_mfa:
                    reason = '(MFA Required) ' + reason

                result.append(Edge(
                    node_source,
                    node_destination,
                    reason,
                    'EC2 Auto Scaling'
                ))

            create_launch_config_auth, clc_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'autoscaling:CreateLaunchConfiguration',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if not create_launch_config_auth:
                continue  # we're done here

            pass_role_auth, pr_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                {
                    'iam:PassedToService': 'ec2.amazonaws.com'
                },
                service_control_policy_groups=scps
            )

            if pass_role_auth:
                if service_role_available:
                    reason = 'can use the EC2 Auto Scaling service role and create a launch configuration to access'
                else:
                    reason = 'can create the EC2 Auto Scaling service role and create a launch configuration to access'
                if clc_mfa or pr_mfa:
                    reason = '(MFA Required) ' + reason

                result.append(Edge(
                    node_source,
                    node_destination,
                    reason,
                    'EC2 Auto Scaling'
                ))

    return result
