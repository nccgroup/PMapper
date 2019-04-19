"""Code for building Graph objects for testing purposes"""

import principalmapper
from principalmapper.common.edges import Edge
from principalmapper.common.graphs import Graph
from principalmapper.common.groups import Group
from principalmapper.common.nodes import Node
from principalmapper.common.policies import Policy


def build_empty_graph() -> Graph:
    """Constructs and returns a Graph object with no nodes, edges, policies, or groups"""
    return Graph([], [], [], [], _get_default_metadata())


def build_graph_with_one_admin() -> Graph:
    """Constructs and returns a Graph object with one node that is an admin"""
    admin_user_arn = 'arn:aws:iam::000000000000:user/admin'
    policy = Policy(admin_user_arn, 'InlineAdminPolicy', _get_admin_policy())
    node = Node(admin_user_arn, [policy], [], None, 1, True, True)
    return Graph([node], [], [policy], [], _get_default_metadata())


def build_playground_graph() -> Graph:
    """Constructs and returns a Graph objects with many nodes, edges, groups, and policies"""
    common_iam_prefix = 'arn:aws:iam::000000000000:'



def _get_admin_policy() -> dict:
    """Constructs and returns a dictionary representing an admin policy"""
    return {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }
        ]
    }


def _get_default_metadata() -> dict:
    """Constructs and returns a metadata dictionary to use across tests"""
    return {'account_id': '000000000000', 'pmapper_version': principalmapper.__version__}
