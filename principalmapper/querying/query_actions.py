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
import os
import re
from typing import Optional

from principalmapper.common import Graph
from principalmapper.querying.presets import privesc, connected
from principalmapper.querying.query_interface import search_authorization_for


def query_response(graph: Graph, query: str, skip_admins: bool = False, output: io.StringIO = os.devnull,
                   debug: bool = False) -> None:
    """Interprets, executes, and outputs the results to a query."""
    result = []

    # Parse
    tokens = re.split(r'\s+', query, flags=re.UNICODE)
    if len(tokens) < 3:
        _write_query_help(output)
        return

    nodes = []

    # first form: "can X do Y with Z when A B C" (principal, action, resource, conditionA, etc.)
    if tokens[0] == 'can' and tokens[2] == 'do':  # can <X> do <Y>
        nodes.append(graph.get_node_by_searchable_name(tokens[1]))
        action = tokens[3]

        if len(tokens) > 5:  # can <X> do <Y> with <Z>
            if tokens[4] != 'with':
                _write_query_help(output)
                return
            resource = tokens[5]
        else:
            resource = '*'

        if len(tokens) > 7:  # can <X> do <Y> with <Z> when <A> and <B> and <C>
            if tokens[6] != 'when':
                _write_query_help(output)
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
        else:
            condition = {}

    # second form: who can do X with Y when Z and A and B and C
    elif tokens[0] == 'who' and tokens[1] == 'can' and tokens[2] == 'do':  # who can do X
        nodes.extend(graph.nodes)
        action = tokens[3]

        if len(tokens) > 5:  # who can do X with Y
            if tokens[4] != 'with':
                _write_query_help(output)
                return
            resource = tokens[5]
        else:
            resource = '*'

        if len(tokens) > 7:  # who can do X with Y when A and B and C
            if tokens[6] != 'when':
                _write_query_help(output)
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
        else:
            condition = {}

    elif tokens[0] == 'preset':
        handle_preset(graph, query, skip_admins, output, debug)
        return

    else:
        _write_query_help(output)
        return

    # Execute
    for node in nodes:
        if not skip_admins or not node.is_admin:
            result.append((
                search_authorization_for(
                    graph,
                    node,
                    action,
                    resource,
                    condition,
                    debug
                ), action, resource)
            )

    # Print
    for query_result, action, resource in result:
        query_result.write_result(action, resource, output)


def handle_preset(graph: Graph, query: str, skip_admins: bool = False, output: io.StringIO = os.devnull,
                  debug: bool = False) -> None:
    """Interprets, executes, and outputs the result to a preset query."""
    tokens = re.split(r'\s+', query, flags=re.UNICODE)
    if tokens[1] == 'privesc':
        privesc.handle_preset_query(graph, tokens, skip_admins, output, debug)
    elif tokens[1] == 'connected':
        connected.handle_preset_query(graph, tokens, skip_admins, output, debug)
    else:
        _write_query_help(output)
        return


def _write_query_help(output: io.StringIO) -> None:
    """Writes information about querying"""
    output.write('Querying Help:\n\n')
    output.write('First form:\n')
    output.write('   can <Principal> do <Action> [with <Resource [when <ConditionA> [and <ConditionB>...]]]\n')
    output.write('Second form:\n')
    output.write('   who can do <Action> [with <Resource> [when <ConditionA> [and <ConditionB>...]]]\n')
    output.write('Third form:\n')
    output.write('   preset <preset args>\n\n')
    output.write('Available presets:\n')
    output.write('* connected (principal|"*") (principal|"*")\n')
    output.write('* privesc (principal|"*")\n')


def argquery(graph: Graph, principal_param: Optional[str], action_param: Optional[str], resource_param: Optional[str],
             condition_param: Optional[dict], preset_param: Optional[str], skip_admins: bool = False,
             output: io.StringIO = os.devnull, debug: bool = False) -> None:
    """Splits between running a normal argquery and the presets."""
    if preset_param is not None:
        if preset_param == 'privesc':
            # Validate params
            if action_param is not None:
                raise ValueError('For the privesc preset query, the --action parameter should not be set.')
            if resource_param is not None:
                raise ValueError('For the privesc preset query, the --resource parameter should not be set.')

            nodes = []
            if principal_param is None or principal_param == '*':
                nodes.extend(graph.nodes)
            else:
                nodes.append(graph.get_node_by_searchable_name(principal_param))

            privesc.write_privesc_results(graph, nodes, skip_admins, output, debug)
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

            connected.write_connected_results(graph, source_nodes, dest_nodes, skip_admins, output, debug)
        else:
            raise ValueError('Parameter for "preset" is not valid. Expected values: "privesc" and "connected".')

    else:
        argquery_response(graph, principal_param, action_param, resource_param, condition_param, skip_admins, output,
                          debug)


def argquery_response(graph: Graph, principal_param: Optional[str], action_param: str, resource_param: Optional[str],
                      condition_param: Optional[dict], skip_admins: bool = False,  output: io.StringIO = os.devnull,
                      debug: bool = False) -> None:
    """Writes the output of an argquery to output."""
    result = []

    if resource_param is None:
        resource_param = '*'

    if condition_param is None:
        condition_param = {}

    if principal_param is None or principal_param == '*':
        for node in graph.nodes:
            if skip_admins:
                if not node.is_admin:
                    result.append(
                        search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))
            else:
                result.append(
                    search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))

    else:
        node = graph.get_node_by_searchable_name(principal_param)
        if skip_admins:
            if not node.is_admin:
                result.append(
                    search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))
        else:
            result.append(search_authorization_for(graph, node, action_param, resource_param, condition_param, debug))

    for query_result in result:
        query_result.write_result(action_param, resource_param, output)
