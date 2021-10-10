"""Code to identify if a principal in an AWS account can use access to SageMaker to access other principals."""

#  Copyright (c) NCC Group and Erik Steringer 2021. This file is part of Principal Mapper.
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
from typing import List, Optional

from principalmapper.common import Edge, Node
from principalmapper.graphing.edge_checker import EdgeChecker
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import resource_policy_authorization, ResourcePolicyEvalResult
from principalmapper.util import arns


logger = logging.getLogger(__name__)


class SageMakerEdgeChecker(EdgeChecker):
    """Class for identifying if Amazon SageMaker can be used by IAM principals to access other principals.

    TODO: add checks for CreateDomain and related operations
    """

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """fulfills expected method"""

        logger.info('Generating Edges based on SageMaker')
        result = generate_edges_locally(nodes, scps)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None) -> List[Edge]:
    """Generates and returns Edge objects. It is possible to use this method if you are operating offline (infra-as-code).
    """

    result = []
    for node_destination in nodes:

        if ':role/' not in node_destination.arn:
            continue  # skip if destination is a user and not a role

        sim_result = resource_policy_authorization(
            'sagemaker.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {}
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # SageMaker is not authorized to assume the role

        for node_source in nodes:
            if node_source == node_destination:
                continue  # skip self-access checks

            if node_source.is_admin:
                continue  # skip if source is already admin, not tracked via edges

            mfa_needed = False
            conditions = {'iam:PassedToService': 'sagemaker.amazonaws.com'}
            pass_role_auth, pass_needs_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                conditions,
                service_control_policy_groups=scps
            )
            if not pass_role_auth:
                continue  # source node is not authorized to pass the role

            create_notebook_auth, needs_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'sagemaker:CreateNotebookInstance',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if create_notebook_auth:
                new_edge = Edge(
                    node_source,
                    node_destination,
                    '(MFA required) can use SageMaker to launch a notebook and access' if pass_needs_mfa or needs_mfa else 'can use SageMaker to launch a notebook and access',
                    'SageMaker'
                )
                result.append(new_edge)

            create_training_auth, needs_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'sagemaker:CreateTrainingJob',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if create_training_auth:
                result.append(Edge(
                    node_source,
                    node_destination,
                    '(MFA required) can use SageMaker to create a training job and access' if pass_needs_mfa or needs_mfa else 'can use SageMaker to create a training job and access',
                    'SageMaker'
                ))

            create_processing_auth, needs_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'sagemaker:CreateProcessingJob',
                '*',
                {},
                service_control_policy_groups=scps
            )

            if create_processing_auth:
                result.append(Edge(
                    node_source,
                    node_destination,
                    '(MFA required) can use SageMaker to create a processing job and access' if pass_needs_mfa or needs_mfa else 'can use SageMaker to create a processing job and access',
                    'SageMaker'
                ))

    return result
