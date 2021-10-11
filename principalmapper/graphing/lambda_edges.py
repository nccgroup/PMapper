"""Code to identify if a principal in an AWS account can use access to Lambda to access other principals."""

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

from botocore.exceptions import ClientError

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.querying import query_interface
from principalmapper.util import arns, botocore_tools


logger = logging.getLogger(__name__)


class LambdaEdgeChecker(EdgeChecker):
    """Class for identifying if Lambda can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges. If session object is None, runs checks in offline mode."""

        logger.info('Pulling data on Lambda functions')

        if client_args_map is None:
            lambdaargs = {}
        else:
            lambdaargs = client_args_map.get('lambda', {})

        lambda_clients = []
        if self.session is not None:
            lambda_regions = botocore_tools.get_regions_to_search(self.session, 'lambda', region_allow_list, region_deny_list)
            for region in lambda_regions:
                lambda_clients.append(self.session.create_client('lambda', region_name=region, **lambdaargs))

        # grab existing lambda functions
        function_list = []
        for lambda_client in lambda_clients:
            try:
                paginator = lambda_client.get_paginator('list_functions')
                for page in paginator.paginate(PaginationConfig={'PageSize': 25}):
                    for func in page['Functions']:
                        function_list.append(func)
            except ClientError as ex:
                logger.warning('Unable to search region {} for stacks. The region may be disabled, or the error may '
                               'be caused by an authorization issue. Continuing.'.format(lambda_client.meta.region_name))
                logger.debug('Exception details: {}'.format(ex))

        logger.info('Generating Edges based on Lambda data.')
        logger.debug('Identified {} Lambda functions for processing'.format(len(function_list)))
        result = generate_edges_locally(nodes, function_list, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], function_list: List[dict], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline
    (infra-as-code), but you must provide a `function_list` that is a list of dictionaries that mimic the
    output of calling `lambda:ListFunctions`.
    """

    result = []
    for node_destination in nodes:
        # check that destination is a role
        if ':role/' not in node_destination.arn:
            continue

        # check that the destination role can be assumed by Lambda
        sim_result = resource_policy_authorization(
            'lambda.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {}
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # Lambda wasn't auth'd to assume the role

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin, if so it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # check that source can pass the destination role (store result for future reference)
            can_pass_role, need_mfa_passrole = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                {
                    'iam:PassedToService': 'lambda.amazonaws.com'
                },
                service_control_policy_groups=scps
            )

            # check that source can create a Lambda function and pass it an execution role
            if can_pass_role:
                can_create_function, need_mfa_0 = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'lambda:CreateFunction',
                    '*',
                    {},
                    service_control_policy_groups=scps
                )
                if can_create_function:
                    if need_mfa_0 or need_mfa_passrole:
                        reason = '(requires MFA) can use Lambda to create a new function with arbitrary code, ' \
                                 'then pass and access'
                    else:
                        reason = 'can use Lambda to create a new function with arbitrary code, then pass and access'
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason,
                        'Lambda'
                    )
                    result.append(new_edge)
                    continue  # TODO: reexamine if it is appropriate to skip the next checks, which can be O(n^2) in some accounts

            func_data = []  # List[Tuple[dict, bool, bool]]
            for func in function_list:
                can_change_code, need_mfa_1 = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'lambda:UpdateFunctionCode',
                    func['FunctionArn'],
                    {},
                    service_control_policy_groups=scps
                )

                func_data.append(
                    (func, can_change_code, need_mfa_passrole or need_mfa_1))

            # check that source can modify a Lambda function and use its existing role
            for func, can_change_code, need_mfa in func_data:
                if node_destination.arn == func['Role']:
                    if can_change_code:
                        if need_mfa:
                            reason = '(requires MFA) can use Lambda to edit an existing function ({}) to access'.format(
                                func['FunctionArn']
                            )
                        else:
                            reason = 'can use Lambda to edit an existing function ({}) to access'.format(
                                func['FunctionArn']
                            )
                        new_edge = Edge(
                            node_source,
                            node_destination,
                            reason,
                            'Lambda'
                        )
                        result.append(new_edge)
                        break

                can_change_config, need_mfa_2 = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'lambda:UpdateFunctionConfiguration',
                    func['FunctionArn'],
                    {},
                    service_control_policy_groups=scps
                )

                if can_change_config and can_change_code and can_pass_role:
                    if need_mfa or need_mfa_2:
                        reason = '(requires MFA) can use Lambda to edit an existing function ({}) to access'.format(
                            func['FunctionArn']
                        )
                    else:
                        reason = 'can use Lambda to edit an existing function ({}) to access'.format(
                            func['FunctionArn']
                        )
                    new_edge = Edge(
                        node_source,
                        node_destination,
                        reason,
                        'Lambda'
                    )
                    result.append(new_edge)
                    break

    return result
