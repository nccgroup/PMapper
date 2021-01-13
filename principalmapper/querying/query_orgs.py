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

from typing import List, Optional

from principalmapper.common import Graph, OrganizationTree, Policy, OrganizationNode


def produce_scp_list(graph: Graph, org: OrganizationTree) -> Optional[List[List[Policy]]]:
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

    def _grab_policies_and_traverse(org_nodes: List[OrganizationNode], parts, index, account_id):
        for org_node in org_nodes:
            if org_node.ou_id != parts[index]:
                continue
            else:
                result.append([x.policy_doc for x in org_node.scps])
                if parts[index + 1] == '':
                    for account in org_node.accounts:
                        if account.account_id == account_id:
                            result.append([x.policy_doc for x in account.scps])
                else:
                    _grab_policies_and_traverse(org_node.child_nodes, parts, index + 1, account_id)

    _grab_policies_and_traverse(org.root_ous, org_path_parts, 1, graph.metadata['account_id'])

    return result
