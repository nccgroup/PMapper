"""Code for executing queries given by the Principal Mapper command-line"""


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
import re
from typing import Optional, List

from principalmapper.common import Graph
from principalmapper.querying.presets import privesc, connected, clusters, endgame, serviceaccess, wrongadmin
from principalmapper.querying.query_interface import search_authorization_for, search_authorization_full
from principalmapper.util import arns


logger = logging.getLogger(__name__)

_query_help_string = """QUERY HELP:

First form:
   can <Principal> do <Action> [with <Resource [when <ConditionA> [and <ConditionB>...]]]
Second form:
   who can do <Action> [with <Resource> [when <ConditionA> [and <ConditionB>...]]]
Third form:
   preset <preset args>

Available presets:
    * connected (principal|"*") (principal|"*")
    * privesc (principal|"*")
    * clusters (tag key)
    * endgame (service|"*")
    * serviceaccess
    * wrongadmin
"""


def query_response(graph: Graph, query: str, skip_admins: bool = False, resource_policy: Optional[dict] = None,
                   resource_owner: Optional[str] = None, include_unauthorized: bool = False,
                   session_policy: Optional[dict] = None, scps: Optional[List[List[dict]]] = None) -> None:
    """Interprets, executes, and outputs the results to a query."""
    result = []

    # Parse
    tokens = re.split(r'\s+', query, flags=re.UNICODE)
    logger.debug('Query tokens: {}'.format(tokens))
    if len(tokens) < 2:
        _print_query_help()
        return

    nodes = []

    # first form: "can X do Y with Z when A B C" (principal, action, resource, conditionA, etc.)
    if tokens[0] == 'can' and tokens[2] == 'do':  # can <X> do <Y>
        nodes.append(graph.get_node_by_searchable_name(tokens[1]))
        action = tokens[3]

        if len(tokens) > 5:  # can <X> do <Y> with <Z>
            if tokens[4] != 'with':
                _print_query_help()
                return
            resource = tokens[5]
        else:
            resource = '*'

        if len(tokens) > 7:  # can <X> do <Y> with <Z> when <A> and <B> and <C>
            if tokens[6] != 'when':
                _print_query_help()
                return

            # doing this funky stuff in case condition values can have spaces
            # we make the (bad, but good enough?) assumption that condition values don't have ' and ' in them
            condition_str = ' '.join(tokens[7:])
            condition_tokens = re.split(r'\s+and\s+', condition_str, flags=re.UNICODE)
            condition = {}
            for condition_token in condition_tokens:
                # split on equals-sign (=), assume first instance separates the key and value
                components = condition_token.split('=')
                if len(components) < 2:
                    raise ValueError('Format for condition args not matched: <key>=<value>')
                key = components[0]
                value = '='.join(components[1:])
                condition.update({key: value})
            logger.debug('Conditions: {}'.format(condition))
        else:
            condition = {}

    # second form: who can do X with Y when Z and A and B and C
    elif tokens[0] == 'who' and tokens[1] == 'can' and tokens[2] == 'do':  # who can do X
        nodes.extend(graph.nodes)
        action = tokens[3]

        if len(tokens) > 5:  # who can do X with Y
            if tokens[4] != 'with':
                _print_query_help()
                return
            resource = tokens[5]
        else:
            resource = '*'

        if len(tokens) > 7:  # who can do X with Y when A and B and C
            if tokens[6] != 'when':
                _print_query_help()
                return

            # doing this funky stuff in case condition values can have spaces
            condition_str = ' '.join(tokens[7:])
            condition_tokens = re.split(r'\s+and\s+', condition_str, flags=re.UNICODE)
            condition = {}
            for condition_token in condition_tokens:
                # split on equals-sign (=), assume first instance separates the key and value
                components = condition_token.split('=')
                if len(components) < 2:
                    raise ValueError('Format for condition args not matched: <key>=<value>')
                key = components[0]
                value = '='.join(components[1:])
                condition.update({key: value})
            logger.debug('Conditions: {}'.format(condition))
        else:
            condition = {}

    elif tokens[0] == 'preset':
        handle_preset(graph, query, skip_admins)
        return

    else:
        _print_query_help()
        return

    # pull resource owner from arg or ARN
    if resource_policy is not None:
        if resource_owner is None:
            arn_owner = arns.get_account_id(resource)
            if '*' in arn_owner or '?' in arn_owner:
                raise ValueError('Resource arg in query cannot have wildcards (? and *) unless setting '
                                 '--resource-owner')
            if arn_owner == '':
                raise ValueError('Param --resource-owner must be set if resource param does not include the '
                                 'account ID.')

    # Execute
    for node in nodes:
        if not skip_admins or not node.is_admin:
            result.append((
                search_authorization_full(
                    graph,
                    node,
                    action,
                    resource,
                    condition,
                    resource_policy,
                    resource_owner,
                    scps,
                    session_policy
                ),
                action,
                resource
            ))

    # Print
    for query_result, action, resource in result:
        if query_result.allowed or include_unauthorized:
            query_result.print_result(action, resource)
            print()


def handle_preset(graph: Graph, query: str, skip_admins: bool = False) -> None:
    """Interprets, executes, and outputs the result to a preset query."""
    tokens = re.split(r'\s+', query, flags=re.UNICODE)
    if tokens[1] == 'privesc':
        if len(tokens) < 3:
            _print_query_help()
            return
        privesc.handle_preset_query(graph, tokens, skip_admins)
    elif tokens[1] == 'connected':
        if len(tokens) < 4:
            _print_query_help()
            return
        connected.handle_preset_query(graph, tokens, skip_admins)
    elif tokens[1] == 'clusters':
        if len(tokens) < 3:
            _print_query_help()
            return
        clusters.handle_preset_query(graph, tokens, skip_admins)
    elif tokens[1] == 'endgame':
        if len(tokens) < 3:
            _print_query_help()
            return
        endgame.handle_preset_query(graph, tokens, skip_admins)
    elif tokens[1] == 'serviceaccess':
        serviceaccess.handle_preset_query(graph, tokens, skip_admins)
    elif tokens[1] == 'wrongadmin':
        wrongadmin.handle_preset_query(graph, tokens, skip_admins)
    else:
        _print_query_help()
        return


def _write_query_help(output: io.StringIO) -> None:
    """Writes information about querying"""
    output.write(_query_help_string)


def _print_query_help() -> None:
    """Prints information about querying"""
    print(_query_help_string.strip())


def argquery(graph: Graph, principal_param: Optional[str], action_param: Optional[str], resource_param: Optional[str],
             condition_param: Optional[dict], preset_param: Optional[str], skip_admins: bool = False,
             resource_policy: dict = None, resource_owner: str = None, include_unauthorized: bool = False,
             session_policy: Optional[dict] = None, scps: Optional[List[List[dict]]] = None) -> None:
    """Splits between running a normal argquery and the presets."""
    if preset_param is not None:
        if preset_param == 'privesc':
            # Validate params
            if action_param is not None:
                raise ValueError('For the privesc preset query, the --action parameter should not be set.')
            if resource_param is not None and resource_param != '*':
                raise ValueError('For the privesc preset query, the --resource parameter should not be set or set to \'*\'.')

            nodes = []
            if principal_param is None or principal_param == '*':
                nodes.extend(graph.nodes)
            else:
                nodes.append(graph.get_node_by_searchable_name(principal_param))

            privesc.print_privesc_results(graph, nodes, skip_admins)
        elif preset_param == 'connected':
            # Validate params
            if action_param is not None:
                raise ValueError('For the privesc preset query, the --action parameter should not be set.')

            source_nodes = []
            dest_nodes = []
            if principal_param is None or principal_param == '*':
                source_nodes.extend(graph.nodes)
            else:
                source_nodes.append(graph.get_node_by_searchable_name(principal_param))

            if resource_param is None or resource_param == '*':
                dest_nodes.extend(graph.nodes)
            else:
                dest_nodes.append(graph.get_node_by_searchable_name(resource_param))

            connected.write_connected_results(graph, source_nodes, dest_nodes, skip_admins)
        elif preset_param == 'clusters':
            # validate params
            if action_param is not None:
                raise ValueError('For the clusters preset query, the --action parameter should not be set.')

            if resource_param is None:
                raise ValueError('For the clusters preset query, the --resource parameter must be set.')

            clusters.handle_preset_query(graph, ['', '', resource_param], skip_admins)
        elif preset_param == 'endgame':
            # validate params
            if action_param is not None:
                raise ValueError('For the clusters preset query, the --action parameter should not be set.')

            if resource_param is None:
                raise ValueError('For the endgame preset query, the --resource parameter must be set.')

            endgame.handle_preset_query(graph, ['', '', resource_param], skip_admins)
        elif preset_param == 'serviceaccess':
            serviceaccess.handle_preset_query(graph, [], skip_admins)
        elif preset_param == 'wrongadmin':
            wrongadmin.handle_preset_query(graph, [], skip_admins)
        else:
            raise ValueError('Parameter for "preset" is not valid. Expected values: "privesc", "connected", '
                             '"clusters", "endgame", "serviceaccess", or "wrongadmin".')

    else:
        argquery_response(graph, principal_param, action_param, resource_param, condition_param, skip_admins,
                          resource_policy, resource_owner, include_unauthorized, session_policy, scps)


def argquery_response(graph: Graph, principal_param: Optional[str], action_param: str, resource_param: Optional[str],
                      condition_param: Optional[dict], skip_admins: bool = False, resource_policy: dict = None,
                      resource_owner: str = None, include_unauthorized: bool = False,
                      session_policy: Optional[dict] = None, scps: Optional[List[List[dict]]] = None) -> None:
    """Prints the output of a non-preset argquery"""
    result = []

    if resource_param is None:
        resource_param = '*'

    if condition_param is None:
        condition_param = {}

    # Collect together nodes
    if principal_param is None or principal_param == '*':
        if skip_admins:
            nodes = [x for x in graph.nodes if not x.is_admin]
        else:
            nodes = graph.nodes
    else:
        target_node = graph.get_node_by_searchable_name(principal_param)
        if skip_admins and target_node.is_admin:
            return
        else:
            nodes = [target_node]

    # go through all nodes
    for node in nodes:
        result.append(
            search_authorization_full(
                graph,
                node,
                action_param,
                resource_param,
                condition_param,
                resource_policy,
                resource_owner,
                scps,
                session_policy
            )
        )

    for query_result in result:
        if query_result.allowed or include_unauthorized:
            query_result.print_result(action_param, resource_param)
            print()
