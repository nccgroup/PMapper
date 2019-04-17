"""Python code for gathering IAM-related information from an AWS account"""

import io
import os

import botocore.session
from principalmapper.common.nodes import Node
from principalmapper.common.groups import Group
from principalmapper.common.graphs import Graph
from principalmapper.util import arns
from principalmapper.util.debug_print import dprint
from typing import List


def create_graph(session: botocore.session.Session, metadata: dict, output: io.StringIO = os.devnull,
                 debug=False) -> Graph:
    """Creates a list of Node objects to use for building a Graph"""
    iamclient = session.create_client('iam')

    # Gather users and roles, generating a Node per user and per role
    nodes_result = get_unfilled_nodes(iamclient, output, debug)

    # Gather groups from current list of nodes (users), generate Group objects, attach to nodes in-flight
    groups_result = []  # TODO: get groups

    # Resolve all policies, generate Policy objects
    policies_result = []  # TODO: get policies

    # Generate edges, generate Edge objects
    edges_result = []  # TODO: get edges

    return Graph(nodes_result, edges_result, policies_result, groups_result, metadata)


def get_unfilled_nodes(iamclient, output: io.StringIO = os.devnull, debug=False) -> List[Node]:
    """Using an IAM.Client object, return a list of Node object for each IAM user and role in an account.

    Does not set Group or Policy objects.

    Writes high-level information on progress to the output file
    """
    result = []
    # Get users, paginating results, still need to handle policies + group memberships + is_admin
    output.write("Obtaining IAM users in account\n")
    user_paginator = iamclient.get_paginator('list_users')
    for page in user_paginator.paginate(PaginationConfig={'PageSize': 25}):
        dprint(debug, 'list_users page: {}'.format(page))
        for user in page['Users']:
            result.append(Node(
                arn=user['Arn'],
                attached_policies=[],
                group_memberships=[],
                trust_policy=None,
                num_access_keys=0,
                active_password='PasswordLastUsed' in user,
                is_admin=False
            ))
            dprint(debug, 'Adding Node for user ' + user['Arn'])

    # Get roles, paginating results, still need to handle policies + is_admin
    output.write("Obtaining IAM roles in account\n")
    role_paginator = iamclient.get_paginator('list_roles')
    for page in role_paginator.paginate(PaginationConfig={'PageSize': 25}):
        dprint(debug, 'list_roles page: {}'.format(page))
        for role in page['Roles']:
            result.append(Node(
                arn=role['Arn'],
                attached_policies=[],
                group_memberships=[],
                trust_policy=role['AssumeRolePolicyDocument'],
                num_access_keys=0,
                active_password=False,
                is_admin=False
            ))

    # Handle access keys
    output.write("Obtaining Access Keys data for IAM users\n")
    for node in result:
        if arns.get_resource(node.arn).startswith('user/'):
            # Grab access-key count and update node
            user_name = arns.get_resource(node.arn)[5:]
            access_keys_data = iamclient.list_access_keys(UserName=user_name)
            node.access_keys = len(access_keys_data['AccessKeyMetadata'])
            dprint(debug, 'Access Key Count for {}: {}'.format(user_name, len(access_keys_data['AccessKeyMetadata'])))

    return result
