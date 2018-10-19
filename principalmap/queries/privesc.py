# privesc.py

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

from principalmap.edgeconditions.util import testAction


class PrivEscQuery:
    """Contains static functions to test if a principal is able to "escalate privileges"
    within an AWS account. Searches if the input principal or any principal
    it can access can escalate privileges.

    Checks include:
        * Principal can edit own inline policy.
        * Principal can create a policy version for an attached policy.
        * Principal can create and attach a managed policy.
        * Principal can do the above for another accessible principal.
    """

    @staticmethod
    def check_self(iamclient, node):
        if node.get_type() == 'user':
            if testAction(iamclient, node.label, 'iam:PutUserPolicy', node.label):
                return True
        if node.get_type() == 'role':
            if testAction(iamclient, node.label, 'iam:PutRolePolicy', node.label):
                return True
        return False

    # args: iam client from botocore, AWSGraph, AWSNode, list of tuples (AWSNode, list of AWSEdge)
    # returns a tuple of int and string
    # int value in the tuple is:
    #    0 -> No priv_esc
    #    1 -> Self PrivEsc (user is an admin by own perms)
    #    2 -> Leveraged PrivEsc (user gets admin through other user)
    @staticmethod
    def run_query(iamclient, graph, origin, node_edgelist_tuples):
        if 'is_admin' not in origin.properties:
            origin.properties['is_admin'] = PrivEscQuery.check_self(iamclient, origin)
        if origin.properties['is_admin']:
            return (1, origin.get_name() + ' is an admin principal.')
        for node_tuple in node_edgelist_tuples:
            if 'is_admin' not in node_tuple[0].properties:
                node_tuple[0].properties['is_admin'] = PrivEscQuery.check_self(iamclient, node_tuple[0])
            if node_tuple[0].properties['is_admin']:
                return (2, PrivEscQuery.explain_path(origin, node_tuple))

        return (0, '')

    @staticmethod
    def explain_path(nodeO, tupleX):
        result = str(nodeO) + " can escalate privileges because:\n"

        result += '   ' + str(nodeO) + ' can access ' + str(tupleX[0]) + " because: \n"
        for edge in tupleX[1]:
            result += '      ' + str(edge.nodeX) + ' ' + edge.longlabel + ' ' + str(edge.nodeY) + "\n"
        result += '   and ' + str(tupleX[0]) + ' can escalate its own privileges.'

        return result

    @staticmethod
    def get_node_edgelist_tuple_for_node(node_edgelist_tuples, node):
        for tuple_x in node_edgelist_tuples:
            if node == tuple_x[0]:
                return tuple_x
        return None

    @staticmethod
    def node_in_list(input_node, thelist):
        for node in thelist:
            if node == input_node:
                return True

    @staticmethod
    def print_help():
        print('PRIV ESC QUERY HELP:')
        print('USAGE: ./principalmap query "(priv_esc|privesc|change_perms) <Principal ARN>"')
        print('WHERE:')
        print('   Principal ARN is the principal to check for "priv-esc" capabilities.')
        print('      (also accepts (user|role)/<principal_name>)')
