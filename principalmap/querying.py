# querying.py

from __future__ import absolute_import, print_function, unicode_literals

import re
import sys

from .queries.privesc import PrivEscQuery
from .queries.util import *


# called from main, takes input string and performs a query based on it
def perform_query(input_str, session, graph):
    iamclient = session.create_client('iam')
    tokens = re.split(r'\s+', input_str, flags=re.UNICODE)
    if tokens[0] == 'can' and tokens[2] == 'do':
        node = grab_node_by_name(tokens[1], graph)
        if node == None:
            print('Could not find a principal with the name: ' + tokens[1])
            sys.exit(-1)
        action = tokens[3]
        if len(tokens) == 4:
            result = test_for_node(session, graph, node, action)
            if result != None:
                print_search_result(result, action)
            else:
                print('Did not find a way for ' + str(node) + ' to do ' + action)
        elif len(tokens) == 6:
            if tokens[4] != 'with':
                query_syntax_and_exit()
            resource = tokens[5]
            result = test_for_node(session, graph, node, action, resource)
            if result != None:
                print_search_result(result, action, resource)
            else:
                print('Did not find a way for ' + str(node) + ' to do ' + action + ' with ' + resource)
        else:
            query_syntax_and_exit()
    elif tokens[0] == 'who' and tokens[1] == 'can' and tokens[2] == 'do':
        action = tokens[3]
        if len(tokens) == 4:
            for node in graph.nodes:
                result = test_for_node(session, graph, node, action)
                if result != None:
                    print_search_result(result, action)
        elif len(tokens) == 6:
            resource = tokens[5]
            for node in graph.nodes:
                result = test_for_node(session, graph, node, action, resource)
                if result != None:
                    print_search_result(result, action, resource)
        else:
            query_syntax_and_exit()
    elif tokens[0] == 'preset':
        if tokens[1] == 'priv_esc' or tokens[1] == 'change_perms':
            if len(tokens) == 3:
                if tokens[2] != '*':
                    node = grab_node_by_name(tokens[2], graph)
                    if node == None:
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
    print(
        '   <Resource> is the full ARN of a resource to test (wildcard by default, do not use with actions that do not specify resources)')
    print('   <preset_name> is a predefined query with a set of args <preset_args>')
    sys.exit(-1)
