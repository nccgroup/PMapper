"""Query preset for testing if a principal can escalate privileges. This is intentionally broken up into multiple
methods to make it usable programmatically. Call can_privesc with a Graph and Node to get results that don't require
parsing text output."""

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
import os
from typing import List

from principalmapper.common import Edge, Node, Graph
from principalmapper.querying.query_utils import get_search_list
from principalmapper.util.arns import get_resource, validate_arn, get_account_id, is_valid_aws_account_id

def handle_preset_query(graph: Graph, tokens: List[str] = [], skip_admins: bool = False) -> None:
    """Handles a human-readable query that's been chunked into tokens, and prints the result."""

    # Get the nodes we're determining can privesc or not
    
    external_access_nodes = determine_external_access(graph)
    print_external_access_results(external_access_nodes)


def determine_external_access(graph: Graph, include_fedenerated: bool = True) -> None:
    """Handles a privesc query and writes the result to output."""
    current_account = graph.metadata['account_id']
    nodes = graph.nodes
    external_access_roles = []
    for node in nodes:
        if not get_resource(node.arn).startswith('role/'):
            continue # skip users
        saml_provider_arn_prefix = f"arn:aws:iam::{current_account}:saml-provider/"
        if not node.trust_policy:
            continue

        allows_external_access = False
        external_accounts = [] # Hold all the accounts found in this trust policy
        for statement in node.trust_policy['Statement']:
            _external_accounts = [] # Hold accounts found in this statement
            if 'Principal' in statement.keys():
                principal = statement.get('Principal')
                
                if type(principal) == str or type(principal) == list:
                    _external_accounts.extend(check_principal_allows_external_access(principal=principal,current_account=current_account))
                
                # Its a dict, need to check each type
                elif type(principal) == dict:
                    if 'AWS' in principal.keys():
                        _external_accounts.extend(check_principal_allows_external_access(principal=principal['AWS'],current_account=current_account))
                    if 'Service' in principal.keys():
                        pass
                    if 'Federated' in principal.keys():
                        if include_fedenerated:
                            _external_accounts.append(principal)
                        pass
                    if not any(key in principal for key in ['Federated', 'Service', 'AWS']):
                        pass # Break on this
                else:
                    pass # Break on this
            else:
                pass # Break on this
            
            if _external_accounts:
                external_accounts.extend(_external_accounts)
        if external_accounts:
            node.allowed_external_access.extend(external_accounts)
            external_access_roles.append(node)

    return external_access_roles
        
def print_external_access_results(nodes: List[Node]) -> None:
    for node in nodes:
        print(f"{node.searchable_name()} allows access to:")
        for account in node.allowed_external_access:
            if type(account) == dict:
                for k,v in account.items():
                    print(f"\t{k}: {v}")
            else:
                print(f"\t{account}")
        pass

def write_privesc_results(graph: Graph, nodes: List[Node], skip_admins: bool, output: io.StringIO) -> None:
    """Handles a privesc query and writes the result to output.

    **Change, v1.1.x:** The `output` param is no longer optional. The `skip_admins` param is no longer optional."""
    for node in nodes:
        if skip_admins and node.is_admin:
            continue  # skip admins

        if node.is_admin:
            output.write('{} is an administrative principal\n'.format(node.searchable_name()))
            continue

        privesc, edge_list = can_privesc(graph, node)
        if privesc:
            end_of_list = edge_list[-1].destination
            # the node can access this admin node through the current edge list, print this info out
            output.write('{} can escalate privileges by accessing the administrative principal {}:\n'.format(
                node.searchable_name(), end_of_list.searchable_name()))
            for edge in edge_list:
                output.write('   {}\n'.format(edge.describe_edge()))


def can_privesc(graph: Graph, node: Node) -> (bool, List[Edge]):
    """Method for determining if a given Node in a Graph can escalate privileges.

    Returns a bool, List[Edge] tuple. The bool indicates if there is a privesc risk, and the List[Edge] component
    describes the path of edges the node would have to take to gain access to the admin node.
    """
    edge_lists = get_search_list(graph, node)
    searched_nodes = []
    for edge_list in edge_lists:
        # check if the node at the end of the list has been looked at yet, skip if so
        end_of_list = edge_list[-1].destination
        if end_of_list in searched_nodes:
            continue

        # add end of list to the searched nodes and do the privesc check
        searched_nodes.append(end_of_list)
        if end_of_list.is_admin:
            return True, edge_list
    return False, None

def check_principal_allows_external_access(principal, current_account):
    # Expected to handle principals that take the following form:
    #   "123456789012" (account id as a string)
    #   "arn:aws:iam::123456789012:root" (an ARN for a user/role/account)
    result = []
    if type(principal) == str:
        if is_valid_aws_account_id(principal):
            if not principal == current_account:
                result.append(principal)
                # return [principal]
                # return True
            else:
                pass # Just break on this to confirm working as intended
        elif validate_arn(principal):
            source_account = get_account_id(principal)
            if not source_account == current_account:
                result.append(principal)
                # return [source_account]
                # return True
            else:
                pass # Allows access to principal(s) in the same account
        else:
            pass # Just break on this to confirm working as intended
    elif type(principal) == list:    
        for _item in principal:
            result.extend(check_principal_allows_external_access(_item, current_account))
    return result