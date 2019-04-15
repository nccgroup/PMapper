# util.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from principalmap.edgeconditions.util import testAction, test_node_access, getResourcePolicy


def test_for_node(session, graph, node, action, resource=None):
    """Tests if a node can do a given action with a given resource."""
    result = None
    iamclient = session.create_client('iam')
    for node_edgelist_tuple in get_relevant_nodes(graph, node):
        if resource is None:
            results = test_node_access(iamclient, node_edgelist_tuple[0], [action])
            if (action, '*', True) in results:
                result = node_edgelist_tuple
                break
        else:
            results = test_node_access(iamclient, node_edgelist_tuple[0], [action], [resource])
            if (action, resource, True) in results:
                result = node_edgelist_tuple
                break
    return result


def print_search_result(node_edgelist_tuple, action, resource=None):
    if len(node_edgelist_tuple[1]) == 0:
        toprint = str(node_edgelist_tuple[0]) + ' can do ' + action
        if resource is not None:
            toprint += ' with ' + resource
        print(toprint)
    else:
        toprint = str(node_edgelist_tuple[1][0].nodeX) + ' can do ' + action
        if resource is not None:
            toprint += ' with ' + resource
        toprint += ' through ' + str(node_edgelist_tuple[0])
        print(toprint)
        for edge in node_edgelist_tuple[1]:
            print('   ' + str(edge.nodeX) + ' ' + edge.longlabel + ' ' + str(edge.nodeY))
        toprint = '   ' + str(node_edgelist_tuple[0]) + ' can do ' + action
        if resource is not None:
            toprint += ' with ' + resource
        print(toprint)


def grab_node_by_name(input_str, graph):
    for node in graph.nodes:
        if input_str == node.label or input_str == str(node):
            return node
    return None


# Given a graph and input_node, find all nodes X where there's a path from
# input_node to X. Return a list of tuple (node, edgelist_to_node)
def get_relevant_nodes(graph, input_node):
    result = []
    seen_node_edgelist_tuples = []
    next_node_edgelist_tuples = []
    next_node_edgelist_tuples.append((input_node, []))

    # while we have nodes to check
    while len(next_node_edgelist_tuples) > 0:
        todo_node_edgelist_tuples = []
        for node_tuple in next_node_edgelist_tuples:
            seen_node_edgelist_tuples.append(node_tuple)
            result.append(node_tuple)
            for edge in graph.edges:
                if edge.nodeX == node_tuple[0]:
                    if not node_in_lists(edge.nodeY, [seen_node_edgelist_tuples, next_node_edgelist_tuples, todo_node_edgelist_tuples]):
                        temp = list(node_tuple[1])
                        temp.append(edge)
                        todo_node_edgelist_tuples.append((edge.nodeY, temp))

        next_node_edgelist_tuples = todo_node_edgelist_tuples
    return result


def node_in_lists(node, listoflists):
    for alist in listoflists:
        for item in alist:
            if item[0] == node:
                return True
    return False
