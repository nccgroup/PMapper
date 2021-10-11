"""Code to identify if a principal in an AWS account can use access to AWS CodeBuild to access other principals."""


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


class CodeBuildEdgeChecker(EdgeChecker):
    """Class for identifying if CodeBuild can be used by IAM principals to gain access to other IAM principals."""

    def return_edges(self, nodes: List[Node], region_allow_list: Optional[List[str]] = None,
                     region_deny_list: Optional[List[str]] = None, scps: Optional[List[List[dict]]] = None,
                     client_args_map: Optional[dict] = None) -> List[Edge]:
        """Fulfills expected method return_edges."""

        logger.info('Generating Edges based on CodeBuild.')

        # Gather projects information for each region

        if client_args_map is None:
            cbargs = {}
        else:
            cbargs = client_args_map.get('codebuild', {})

        codebuild_clients = []
        if self.session is not None:
            cf_regions = botocore_tools.get_regions_to_search(self.session, 'codebuild', region_allow_list, region_deny_list)
            for region in cf_regions:
                codebuild_clients.append(self.session.create_client('codebuild', region_name=region, **cbargs))

        codebuild_projects = []
        for cb_client in codebuild_clients:
            logger.debug('Looking at region {}'.format(cb_client.meta.region_name))
            region_project_list_list = []
            try:
                # list the projects first, 50 at a time
                paginator = cb_client.get_paginator('list_projects')
                for page in paginator.paginate(PaginationConfig={'MaxItems': 50}):
                    if 'projects' in page and len(page['projects']) > 0:
                        region_project_list_list.append(page['projects'])

                for region_project_list in region_project_list_list:
                    batch_project_data = cb_client.batch_get_projects(names=region_project_list)  # no pagination
                    if 'projects' in batch_project_data:
                        for project_data in batch_project_data['projects']:
                            if 'serviceRole' in project_data:
                                codebuild_projects.append({
                                    'project_arn': project_data['arn'],
                                    'project_role': project_data['serviceRole'],
                                    'project_tags': project_data['tags']
                                })

            except ClientError as ex:
                logger.warning('Unable to search region {} for projects. The region may be disabled, or the error may '
                               'be caused by an authorization issue. Continuing.'.format(cb_client.meta.region_name))
                logger.debug('Exception details: {}'.format(ex))

        result = generate_edges_locally(nodes, scps, codebuild_projects)

        for edge in result:
            logger.info("Found new edge: {}".format(edge.describe_edge()))

        return result


def _gen_resource_tag_conditions(tag_list: List[dict]):
    condition_result = {
        # 'aws:TagKeys': []
    }
    for tag in tag_list:
        condition_result.update({
            'aws:ResourceTag/{}'.format(tag['key']): tag['value']
        })
        # TODO: make sure we're handling RequestTag and TagKeys correctly
        # condition_result.update({
        #     'aws:RequestTag/{}'.format(tag['Key']): tag['Value']
        # })
        # condition_result['aws:TagKeys'].append(tag['Key'])
    return condition_result


def generate_edges_locally(nodes: List[Node], scps: Optional[List[List[dict]]] = None, codebuild_projects: Optional[List[dict]] = None) -> List[Edge]:
    """Generates and returns Edge objects related to AWS CodeBuild.

    It is possible to use this method if you are operating offline (infra-as-code). The `codebuild_projects` param
    should be a list of dictionary objects with the following expected structure:

    ```
    {
        'project_arn': <str: ARN of a project>,
        'project_role': <str: ARN of a role attached to a project>
        'project_tags': <list[dict]: tags for the project as in [{'Key': <Key>, 'Value': <Value>}]>
    }
    ```

    All elements are required, tags must point to an empty list if there are no tags attached to the project
    """

    result = []

    # we wanna create a role -> [{proj_arn: <>, proj_tags: <>}] map to make eventual lookups faster
    if codebuild_projects is None:
        codebuild_map = {}
    else:
        codebuild_map = {}  # type: Dict[str, List[dict]]
        for project in codebuild_projects:
            if project['project_role'] not in codebuild_map:
                codebuild_map[project['project_role']] = [{'proj_arn': project['project_arn'], 'proj_tags': project['project_tags']}]
            else:
                codebuild_map[project['project_role']].append({'proj_arn': project['project_arn'], 'proj_tags': project['project_tags']})

    for node_destination in nodes:
        # check if destination is a user, skip if so
        if ':role/' not in node_destination.arn:
            continue

        # check that the destination role can be assumed by CodeBuild
        sim_result = resource_policy_authorization(
            'codebuild.amazonaws.com',
            arns.get_account_id(node_destination.arn),
            node_destination.trust_policy,
            'sts:AssumeRole',
            node_destination.arn,
            {},
        )

        if sim_result != ResourcePolicyEvalResult.SERVICE_MATCH:
            continue  # CodeBuild wasn't auth'd to assume the role

        for node_source in nodes:
            # skip self-access checks
            if node_source == node_destination:
                continue

            # check if source is an admin: if so, it can access destination but this is not tracked via an Edge
            if node_source.is_admin:
                continue

            # check if source can use existing projects
            if node_destination.arn in codebuild_map:
                projects = codebuild_map[node_destination.arn]
                for project in projects:
                    startproj_auth, startproj_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'codebuild:StartBuild',
                        project['proj_arn'],
                        _gen_resource_tag_conditions(project['proj_tags']),
                        service_control_policy_groups=scps
                    )
                    if startproj_auth:
                        result.append(Edge(
                            node_source,
                            node_destination,
                            '(MFA Required) can use CodeBuild with an existing project to access' if startproj_mfa else 'can use CodeBuild with an existing project to access',
                            'CodeBuild'
                        ))
                        break  # break out of iterating through projects

                    batchstartproj_auth, batchstartproj_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'codebuild:StartBuildBatch',
                        project['proj_arn'],
                        _gen_resource_tag_conditions(project['proj_tags']),
                        service_control_policy_groups=scps
                    )
                    if batchstartproj_auth:
                        result.append(Edge(
                            node_source,
                            node_destination,
                            '(MFA Required) can use CodeBuild with an existing project to access' if startproj_mfa else 'can use CodeBuild with an existing project to access',
                            'CodeBuild'
                        ))
                        break  # break out of iterating through projects

            # check if source can create/update a project, pass this role, then start a build
            condition_keys = {'iam:PassedToService': 'codebuild.amazonaws.com'}
            pass_role_auth, pass_role_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'iam:PassRole',
                node_destination.arn,
                condition_keys,
                service_control_policy_groups=scps
            )

            if not pass_role_auth:
                continue  # if we can't pass this role, then we're done

            # check if the source can create a project and start a build
            create_proj_auth, create_proj_mfa = query_interface.local_check_authorization_handling_mfa(
                node_source,
                'codebuild:CreateProject',
                '*',
                {},
                service_control_policy_groups=scps
            )
            if create_proj_auth:
                startproj_auth, startproj_mfa = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'codebuild:StartBuild',
                    '*',
                    {},
                    service_control_policy_groups=scps
                )
                if startproj_auth:
                    result.append(Edge(
                        node_source,
                        node_destination,
                        '(MFA Required) can create a project in CodeBuild to access' if create_proj_mfa or pass_role_mfa else 'can create a project in CodeBuild to access',
                        'CodeBuild'
                    ))
                else:
                    batchstartproj_auth, batchstartproj_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'codebuild:StartBuildBatch',
                        '*',
                        {},
                        service_control_policy_groups=scps
                    )
                    if batchstartproj_auth:
                        result.append(Edge(
                            node_source,
                            node_destination,
                            '(MFA Required) can create a project in CodeBuild to access' if create_proj_mfa or pass_role_mfa else 'can create a project in CodeBuild to access',
                            'CodeBuild'
                        ))

            # check if the source can update a project and start a build
            for project in codebuild_projects:
                update_proj_auth, update_proj_mfa = query_interface.local_check_authorization_handling_mfa(
                    node_source,
                    'codebuild:UpdateProject',
                    project['project_arn'],
                    _gen_resource_tag_conditions(project['project_tags']),
                    service_control_policy_groups=scps
                )
                if update_proj_auth:
                    startproj_auth, startproj_mfa = query_interface.local_check_authorization_handling_mfa(
                        node_source,
                        'codebuild:StartBuild',
                        project['project_arn'],
                        _gen_resource_tag_conditions(project['project_tags']),
                        service_control_policy_groups=scps
                    )
                    if startproj_auth:
                        result.append(Edge(
                            node_source,
                            node_destination,
                            '(MFA Required) can update a project in CodeBuild to access' if create_proj_mfa or pass_role_mfa else 'can update a project in CodeBuild to access',
                            'CodeBuild'
                        ))
                        break  # just wanna find that there exists one updatable/usable project
                    else:
                        batchstartproj_auth, batchstartproj_mfa = query_interface.local_check_authorization_handling_mfa(
                            node_source,
                            'codebuild:StartBuildBatch',
                            project['project_arn'],
                            _gen_resource_tag_conditions(project['project_tags']),
                            service_control_policy_groups=scps
                        )
                        if batchstartproj_auth:
                            result.append(Edge(
                                node_source,
                                node_destination,
                                '(MFA Required) can update a project in CodeBuild to access' if create_proj_mfa or pass_role_mfa else 'can update a project in CodeBuild to access',
                                'CodeBuild'
                            ))
                            break  # just wanna find that there exists one updatable/usable project

    return result
