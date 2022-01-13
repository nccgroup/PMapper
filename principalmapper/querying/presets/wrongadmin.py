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

import copy
import json
import logging
import re
from typing import List, Dict, Tuple, Optional

from principalmapper.common import Graph, Policy, Node
from principalmapper.querying import query_interface
from principalmapper.querying.local_policy_simulation import policy_has_matching_statement
from principalmapper.util import arns
from principalmapper.util.case_insensitive_dict import CaseInsensitiveDict


logger = logging.getLogger(__name__)


def handle_preset_query(graph: Graph, tokens: List[str], skip_admins: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and prints the results. Prints out the
    principals in the account who are marked Admin but do not have the AdministratorAccess managed policy or an
    inline equivalent.

    Tokens should be:

    * "preset"
    * "wrongadmin"
    """

    wal = compose_wrong_admin_list(graph)
    for node, reasons in wal:
        print('{}'.format(node.searchable_name()))
        for reason in reasons:
            print('    * {}'.format(reason))
        print()


def _is_admin_or_equiv_policy(policy: Policy) -> bool:
    """Given a Policy return true if the policy is the AdministratorAccess policy or if the policy document
    is effectively the same."""

    if ':aws:policy/AdministratorAccess' in policy.arn:
        return True

    for stmt in policy.policy_doc['Statement']:
        action_flag, resource_flag = False, False
        if 'Action' in stmt and 'Resource' in stmt and stmt['Effect'] == 'Allow':
            if isinstance(stmt['Action'], str):
                if stmt['Action'] == '*':
                    action_flag = True
            else:
                for action in stmt['Action']:
                    if action == '*':
                        action_flag = True
                        break

            if isinstance(stmt['Resource'], str):
                if stmt['Resource'] == '*':
                    resource_flag = True
            else:
                for resource in stmt['Resource']:
                    if resource == '*':
                        resource_flag = True
                        break
        if action_flag and resource_flag:
            return True

    return False


def _get_admin_reason(node: Node) -> List[str]:
    """Return a list of reasons why this given node is an admin."""

    result = []
    logger.debug("Checking if {} is an admin".format(node.searchable_name()))
    node_type = arns.get_resource(node.arn).split('/')[0]

    # check if node can modify its own inline policies
    if node_type == 'user':
        action = 'iam:PutUserPolicy'
    else:  # node_type == 'role'
        action = 'iam:PutRolePolicy'
    if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, {})[0]:
        result.append('Can call {} to add/update their own inline policies'.format(action))

    # check if node can attach the AdministratorAccess policy to itself
    if node_type == 'user':
        action = 'iam:AttachUserPolicy'
    else:
        action = 'iam:AttachRolePolicy'
    condition_keys = {'iam:PolicyARN': 'arn:aws:iam::aws:policy/AdministratorAccess'}
    if query_interface.local_check_authorization_handling_mfa(node, action, node.arn, condition_keys)[0]:
        result.append('Can call {} to attach the AdministratorAccess policy to itself'.format(action))

    # check if node can create a role and attach the AdministratorAccess policy or an inline policy
    if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreateRole', '*', {})[0]:
        if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachRolePolicy', '*',
                                                                  condition_keys)[0]:
            result.append('Can create an IAM Role (iam:CreateRole) and attach the AdministratorAccess policy to it (iam:AttachRolePolicy)'.format(action))
        if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutRolePolicy', '*', condition_keys)[0]:
            result.append('Can create an IAM Role (iam:CreateRole) and create an inline policy for it (iam:PutRolePolicy)'.format(action))

    # check if node can update an attached customer-managed policy (assumes SetAsDefault is set to True)
    for attached_policy in node.attached_policies:
        if attached_policy.arn != node.arn and ':aws:policy/' not in attached_policy.arn:
            if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion',
                                                                      attached_policy.arn, {})[0]:
                result.append('Can modify the attached managed policy {} (iam:CreatePolicyVersion)'.format(attached_policy.arn))
                break  # reduce output

    # check if node is a user, and if it can attach or modify any of its groups's policies
    if node_type == 'user':
        for group in node.group_memberships:
            group_name = group.arn.split('/')[-1]

            if query_interface.local_check_authorization_handling_mfa(node, 'iam:PutGroupPolicy', group.arn, {})[0]:
                result.append('Can add/update an inline policy for the group {} (iam:PutGroupPolicy)'.format(group_name))

            if query_interface.local_check_authorization_handling_mfa(node, 'iam:AttachGroupPolicy', group.arn,
                                                                      condition_keys)[0]:
                result.append('Can attach the AdministratorAccess policy to the group {} (iam:AttachGroupPolicy)'.format(group_name))

            for attached_policy in group.attached_policies:
                if attached_policy.arn != group.arn and ':aws:policy/' not in attached_policy.arn:
                    if query_interface.local_check_authorization_handling_mfa(node, 'iam:CreatePolicyVersion',
                                                                              attached_policy.arn, {})[0]:
                        result.append('Can update the managed policy {} that is attached to the group {} (iam:CreatePolicyVersion)'.format(attached_policy.arn, group_name))
                        break  # reduce output

    return result


def compose_wrong_admin_list(graph: Graph) -> List[Tuple[Node, List[str]]]:
    """Given a Graph, return the collection of principals that are admins but do not have the
    AdminstratorAccess policy or an equivalent inline policy, along with a list of what policy/policies
    and statements that could be the source of the admin-access."""

    result = []

    # iterate through all nodes
    for node in graph.nodes:

        # skip non-admins
        if not node.is_admin:
            continue

        # skip principals with Admin or equiv policy
        flag = False
        for attached_policy in node.attached_policies:
            if _is_admin_or_equiv_policy(attached_policy):
                flag = True
                break
        if flag:
            continue

        # skip IAM Users in IAM Groups with Admin or equiv policy
        if ':user/' in node.arn:
            flag = False
            for group in node.group_memberships:
                for attached_policy in group.attached_policies:
                    if _is_admin_or_equiv_policy(attached_policy):
                        flag = True
                        break
                if flag:
                    break
            if flag:
                continue

        # at this point we have a node that's an admin, so let's find the potentially responsible statements
        result.append((node, _get_admin_reason(node)))

    return result
