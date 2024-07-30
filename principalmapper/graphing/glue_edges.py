"""Code to identify if a principal in an AWS account can use access to AWS Glue to access other principals."""


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


class GlueEdgeChecker(EdgeChecker):
    """Class for identifying if Glue can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on Glue.')

        # Gather projects information for each region

        if client_args_map is None:
            glueargs = {}
        else:
            glueargs = client_args_map.get('glue', {})

        glue_clients = []
        if self.session is not None:
            cf_regions = botocore_tools.get_regions_to_search(self.session, 'glue', region_allow_list, region_deny_list)
            for region in cf_regions:
                glue_clients.append(self.session.create_client('glue', region_name=region, **glueargs))

        endpoint_role_list = []
        for glue_client in glue_clients:
            current_region = glue_client.meta.region_name
            logger.debug(f'Looking at region {current_region}')

            try:
                # paginate thru existing Glue Dev Endpoints
                for page in glue_client.get_paginator('get_dev_endpoints').paginate():
                    for endpoint in page['DevEndpoints']:
                        role_node = None
                        if 'RoleArn' in endpoint:
                            for node in nodes:
                                if node.arn == endpoint['RoleArn']:
                                    role_node = node
                                    break

                        if len(nodes) == 0:
                            break  # causes false-negatives if there's no users/roles in the account
                        endpoint_arn = f'arn:aws:glue:{current_region}:{arns.get_account_id(nodes[0].arn)}:' \
                                       f'devEndpoint/{endpoint["EndpointName"]}'
                        endpoint_role_list.append((endpoint_arn, role_node))

            except ClientError as ex:
                logger.warning('Unable to search region {} for projects. The region may be disabled, or the error may '
                               'be caused by an authorization issue. Continuing.'.format(glue_client.meta.region_name))
                logger.debug('Exception details: {}'.format(ex))

        result = generate_edges_locally(nodes, scps, endpoint_role_list)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None,
                           endpoint_role_list: Optional[List[tuple]] = None) -> List[Edge]:

    results = []

    # to make things faster, we build a Role -> Endpoint map to reduce iterations through endpoint_role_list
    node_endpoint_map = {}
    if endpoint_role_list is not None:
        for endpoint_arn, role_node in endpoint_role_list:
            if role_node is not None and role_node not in node_endpoint_map:
                node_endpoint_map[role_node] = [endpoint_arn]
            else:
                node_endpoint_map[role_node].append(endpoint_arn)

    # for all potential destination nodes...
    for node_destination in nodes:

        # filter down to roles...
        if ':role/' not in node_destination.arn:
            continue

        # filter down to roles assumable by glue.amazonaws.com
        sim_result = resource_policy_authorization(
            'glue.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {},
        )
        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # Glue wasn't auth'd to assume the role

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # check if source can use existing endpoints to access destination
            if node_destination in node_endpoint_map:
                for target_endpoint in node_endpoint_map[node_destination]:
                    update_ep_auth, update_ep_needs_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'glue:UpdateDevEndpoint',
                        target_endpoint,
                        {},
                        service_control_policy_groups=scps
                    )
                    if update_ep_auth:
                        if update_ep_needs_mfa:
                            reason = f'(requires MFA) can use the Glue resource {target_endpoint} to access'
                        else:
                            reason = f'can use the Glue resource {target_endpoint} to access'
                        results.append(Edge(
                            node_source,
                            node_destination,
                            reason,
                            'Glue'
                        ))
                        break

            # check if source can create a new endpoint to access destination
            passrole_auth, passrole_needs_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                {'iam:PassedToService': 'glue.amazonaws.com'},
                service_control_policy_groups=scps
            )

            if passrole_auth:
                create_ep_auth, create_ep_needs_mfa = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'glue:CreateDevEndpoint',
                    '*',
                    {},
                    service_control_policy_groups=scps
                )

                if create_ep_auth:
                    if passrole_needs_mfa or create_ep_needs_mfa:
                        reason = '(requires MFA) can call glue:CreateDevEndpoint to access'
                    else:
                        reason = 'can call glue:CreateDevEndpoint to access'
                    results.append(Edge(
                        node_source,
                        node_destination,
                        reason,
                        'Glue'
                    ))

    return results