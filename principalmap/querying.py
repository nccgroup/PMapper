# querying.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import botocore.session
import re
import sys

from .awsgraph import AWSGraph
from .queries.util import *
from .queries.privesc import PrivEscQuery


def handle_single_query(tokens, session, graph):
    """This function handles queries in the form of:
       "can <Principal> do <Action> [with <Resource>]

    It also prints the result.
    """

    if len(tokens) != 4 and len(tokens) != 6:
        query_syntax_and_exit()

    node = grab_node_by_name(tokens[1], graph)
    if node is None:
        print('Could not find a principal matching: ' + tokens[1])
        return

    action = tokens[3]
    resource = None
    if len(tokens) == 6:
        if tokens[4] != 'with':
            query_syntax_and_exit()
        resource = tokens[5]

    result = test_for_node(session, graph, node, action, resource)
    if result is not None:
        print_search_result(result, action, resource)
    else:
        resource_str = ""
        if len(tokens) == 6:
            resource_str = " with " + resource
        print('Did not find a way for ' + str(node) + ' to do ' + action + resource_str)

def handle_multi_query(tokens, session, graph, skip_admin):
    """This function handles queries in the form of:
       "who can do <Action> [with <Resource>]

    It also prints the result.
    """

    if len(tokens) != 4 and len(tokens) != 6:
        query_syntax_and_exit()

    action = tokens[3]
    for node in graph.nodes:
        if skip_admin and 'is_admin' in node.properties and node.properties['is_admin']:
            continue

        resource = None
        if len(tokens) == 6:
            resource = tokens[5]
        result = test_for_node(session, graph, node, action, resource)

        if result is not None:
            print_search_result(result, action, resource)

def handle_preset_priv_esc(tokens, session, graph, skip_admin):
    """This function handles the "priv_esc / change_perms / privesc" preset queries."""

    pass

def handle_preset_connected(tokens, session, graph):
    """This function handles the "connected" preset queries."""

    pass

def perform_query(input_str, session, graph, skip_admin):
    """Given an input query, this function parses and performs the query."""

    iamclient = session.create_client('iam')
    tokens = re.split(r'\s+', input_str, flags=re.UNICODE)
    if tokens[0] == 'can' and tokens[2] == 'do':
        handle_single_query(tokens, session, graph)
    elif tokens[0] == 'who' and tokens[1] == 'can' and tokens[2] == 'do':
        handle_multi_query(tokens, session, graph, skip_admin)
    elif tokens[0] == 'preset':
        if tokens[1] == 'priv_esc' or tokens[1] == 'change_perms':
            if len(tokens) == 3:
                if tokens[2] != '*':
                    node = grab_node_by_name(tokens[2], graph)
                    if node is None:
                        print('Could not find a principal with the name: ' + tokens[2])
                        sys.exit(-1)
                    node_edgelist_tuples = get_relevant_nodes(graph, node)
                    tuple_result = PrivEscQuery.run_query(iamclient, graph, node, node_edgelist_tuples)
                    if tuple_result[0] != 0:
                        print('Discovered a potential path to change privileges:')
                        print(tuple_result[1])
                    else:
                        print('Did not find a path to change privileges.')
                else:
                    print('====================')
                    for node in graph.nodes:
                        if skip_admin and 'is_admin' in node.properties and node.properties['is_admin']:
                            continue
                        node_edgelist_tuples = get_relevant_nodes(graph, node)
                        tuple_result = PrivEscQuery.run_query(iamclient, graph, node, node_edgelist_tuples)
                        if tuple_result[0] != 0:
                            print(tuple_result[1])
                            print('====================')
            else:
                PrivEscQuery.print_help()
                sys.exit(-1)
        else:
            print('PRESET QUERY LIST:')
            print('   * priv_esc (a.k.a. change_perms)')
            query_syntax_and_exit()
    else:
        query_syntax_and_exit()


def query_syntax_and_exit():
    print('QUERY SYNTAX')
    print('Form 1:')
    print('   "can <Principal> do <Action> [with <Resource>]"')
    print('Form 2:')
    print('   "who can do <Action> [with <Resource>]"')
    print('Form 3:')
    print('   "preset <preset_name> [<preset_args>]"')
    print('WHERE')
    print('   <Principal> is the full ARN of a principal to test')
    print('   <Action> is an action specified by the AWS API')
    print('   <Resource> is the full ARN of a resource to test (wildcard by default, do not use with actions that do not specify resources)')
    print('   <preset_name> is a predefined query with a set of args <preset_args>')
    sys.exit(-1)
