"""Code for helping run queries when AWS Organizations are involved"""

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

from principalmapper.common import Graph, OrganizationTree, Policy, OrganizationNode


logger = logging.getLogger(__name__)


def _grab_policies_and_traverse(org_nodes: List[OrganizationNode], parts, index, account_id, result):
    for org_node in org_nodes:
        if org_node.ou_id != parts[index]:
            continue
        else:
            # ASSUMPTION: all OUs/Accounts in an org HAVE to have at least one policy when SCPs are enabled, so this
            # catches the alternative and does an early return of None. None is interpreted by querying mechanisms
            # as meaning SCPs are NOT considered during authorization
            if len(org_node.scps) == 0:
                return None
            result.append([x.policy_doc for x in org_node.scps])
            if parts[index + 1] == '':
                for account in org_node.accounts:
                    if account.account_id == account_id:
                        result.append([x.policy_doc for x in account.scps])
            else:
                _grab_policies_and_traverse(org_node.child_nodes, parts, index + 1, account_id, result)


def _find_path_or_traverse(search_path: List[str], org_nodes: List[OrganizationNode], target_account: str):
    logger.debug(search_path)
    for org_node in org_nodes:
        search_path.append(org_node.ou_id)
        if target_account in [x.account_id for x in org_node.accounts]:
            return '/'.join(search_path) + '/'
        else:
            traverse_result = _find_path_or_traverse(search_path, org_node.child_nodes, target_account)
            if traverse_result is not None:
                return traverse_result
        search_path.pop()
    return None


def produce_scp_list_by_account_id(account_id: str, org: OrganizationTree) -> Optional[List[List[dict]]]:
    """Given a Graph object and its encompassing OrganizationTree data, produce the hierarchy of SCPs that can be
    fed to `local_check_authorization_full`.

    If the graph belongs to the account that is the management account for the organization, then we return None
    because SCPs cannot restrict the management account's authorization behavior. When we pass None to
    `local_check_authorization_full`, that means that it won't include SCPs during simulation which is what we
    want in that case.

    This version differs from `produce_scp_list` in that it does not require the full Graph object. This is
    useful during the graph-creation process so that we can handle SCPs."""

    result = []

    search_stack = [org.org_id]
    search_path = _find_path_or_traverse(search_stack, org.root_ous, account_id)
    logger.debug('Account organization path: {}'.format(search_path))
    search_path_parts = search_path.split('/')
    _grab_policies_and_traverse(org.root_ous, search_path_parts, 1, account_id, result)

    return result


def produce_scp_list(graph: Graph, org: OrganizationTree) -> Optional[List[List[dict]]]:
    """Given a Graph object and its encompassing OrganizationTree data, produce the hierarchy of SCPs that can be
    fed to `local_check_authorization_full`.

    If the graph belongs to the account that is the management account for the organization, then we return None
    because SCPs cannot restrict the management account's authorization behavior. When we pass None to
    `local_check_authorization_full`, that means that it won't include SCPs during simulation which is what we
    want in that case."""

    if 'org-id' not in graph.metadata or 'org-path' not in graph.metadata:
        raise ValueError('Given graph for account {} does not have AWS Organizations data (try running '
                         '`pmapper orgs create/update`).')

    if graph.metadata['account_id'] == org.management_account_id:
        return None

    result = []

    # org-path is in the form '<organization ID>/<root ID>/[<OU 1>/<OU 2>/<OU N>/]' so we split and start from [1]
    org_path_parts = graph.metadata['org-path'].split('/')

    _grab_policies_and_traverse(org.root_ous, org_path_parts, 1, graph.metadata['account_id'], result)

    return result
